package nhom06.gateway;

import nhom06.common.Log;
import nhom06.common.Protocol;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bộ lọc gói tin của Gateway.
 *
 * - Luật được duyệt theo thứ tự trong file, ÁP DỤNG LUẬT KHỚP ĐẦU TIÊN
 *   (first-match-wins) giống ACL của Cisco / iptables.
 * - Nếu không luật nào khớp thì dùng chính sách mặc định theo chiều (POLICY).
 * - Bộ lọc là STATEFUL: gói tin đi về trên một phiên đã có trong bảng NAT
 *   được cho qua mà không cần luật IN, đúng như hành vi của NAT firewall thật.
 * - Tích hợp phát hiện quét cổng: nếu một IP bên ngoài bị chặn ở nhiều cổng
 *   khác nhau trong một khoảng thời gian ngắn thì phát cảnh báo an ninh.
 */
public class Firewall {

    /** Kết quả kiểm tra: cho qua hay không, và luật nào đã quyết định. */
    public static class Decision {
        public final boolean allowed;
        public final String reason;

        Decision(boolean allowed, String reason) {
            this.allowed = allowed;
            this.reason = reason;
        }
    }

    private final List<FirewallRule> rules = new CopyOnWriteArrayList<>();
    private volatile FirewallRule.Action defaultOut = FirewallRule.Action.ALLOW;
    private volatile FirewallRule.Action defaultIn = FirewallRule.Action.DENY;
    private final String rulesFile;

    private final AtomicLong allowedCount = new AtomicLong();
    private final AtomicLong deniedCount = new AtomicLong();
    private final AtomicLong defaultInHits = new AtomicLong();
    private final AtomicLong defaultOutHits = new AtomicLong();

    // --- Phát hiện quét cổng & Auto-ban ---
    private final int scanThreshold;
    private final long scanWindowMs;
    private final ConcurrentHashMap<String, Map<Integer, Long>> deniedProbes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastAlert = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> bannedIps = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> banReasons = new ConcurrentHashMap<>();

    public Firewall(String rulesFile, int scanThreshold, long scanWindowMs) {
        this.rulesFile = rulesFile;
        this.scanThreshold = scanThreshold;
        this.scanWindowMs = scanWindowMs;
        load();
    }

    public synchronized void ban(String ip, long durationMs, String reason) {
        long until = System.currentTimeMillis() + durationMs;
        bannedIps.put(ip, until);
        banReasons.put(ip, reason);
        Log.alert("SECURITY", "AUTO-BAN IP " + ip + " trong " + (durationMs / 1000) + "s. Ly do: " + reason);
    }

    public synchronized boolean unban(String ip) {
        boolean removed = bannedIps.remove(ip) != null;
        banReasons.remove(ip);
        if (removed) Log.info("FIREWALL", "Da UNBAN cho IP: " + ip);
        return removed;
    }

    public boolean isBanned(String ip) {
        Long until = bannedIps.get(ip);
        if (until == null) return false;
        if (System.currentTimeMillis() > until) {
            bannedIps.remove(ip);
            banReasons.remove(ip);
            Log.info("FIREWALL", "Da het han AUTO-BAN cho IP: " + ip);
            return false;
        }
        return true;
    }

    public Map<String, String> bannedIpsSummary() {
        long now = System.currentTimeMillis();
        bannedIps.entrySet().removeIf(e -> now > e.getValue());
        Map<String, String> res = new HashMap<>();
        bannedIps.forEach((ip, until) -> {
            long left = Math.max(0, (until - now) / 1000);
            res.put(ip, left + "s (" + banReasons.getOrDefault(ip, "vi pham") + ")");
        });
        return res;
    }

    public final synchronized void load() {
        List<FirewallRule> loaded = new ArrayList<>();
        FirewallRule.Action dOut = FirewallRule.Action.ALLOW;
        FirewallRule.Action dIn = FirewallRule.Action.DENY;

        try (BufferedReader br = new BufferedReader(new FileReader(rulesFile))) {
            String line;
            int n = 0;
            while ((line = br.readLine()) != null) {
                n++;
                String t = line.trim();
                if (t.toUpperCase().startsWith("POLICY")) {
                    String[] p = t.split("\\s+");
                    if (p.length >= 3) {
                        FirewallRule.Action act = FirewallRule.Action.valueOf(p[2].toUpperCase());
                        if (p[1].equalsIgnoreCase("OUT")) dOut = act;
                        else if (p[1].equalsIgnoreCase("IN")) dIn = act;
                    }
                    continue;
                }
                FirewallRule r = FirewallRule.parse(line, n);
                if (r != null) loaded.add(r);
            }
        } catch (IOException e) {
            Log.error("FIREWALL", "Khong doc duoc file luat '" + rulesFile
                    + "' -> chay voi chinh sach mac dinh (OUT=ALLOW, IN=DENY).");
        }

        rules.clear();
        rules.addAll(loaded);
        defaultOut = dOut;
        defaultIn = dIn;
        Log.info("FIREWALL", "Da nap " + rules.size() + " luat. Mac dinh: OUT=" + defaultOut + ", IN=" + defaultIn);
    }

    public Decision check(FirewallRule.Direction dir, Protocol proto,
                          String srcIp, int srcPort, String dstIp, int dstPort) {
        if (isBanned(srcIp)) {
            deniedCount.incrementAndGet();
            return new Decision(false, "AUTO-BAN: IP " + srcIp + " dang bi tam khoa");
        }
        for (FirewallRule r : rules) {
            if (r.matches(dir, proto, srcIp, srcPort, dstIp, dstPort)) {
                r.hit();
                boolean allow = (r.action == FirewallRule.Action.ALLOW);
                count(allow);
                return new Decision(allow, "luat #" + r.lineNumber + " [" + r.raw + "]");
            }
        }
        FirewallRule.Action def = (dir == FirewallRule.Direction.IN) ? defaultIn : defaultOut;
        if (dir == FirewallRule.Direction.IN) defaultInHits.incrementAndGet();
        else defaultOutHits.incrementAndGet();
        boolean allow = (def == FirewallRule.Action.ALLOW);
        count(allow);
        return new Decision(allow, "chinh sach mac dinh " + dir + "=" + def);
    }

    private void count(boolean allowed) {
        if (allowed) allowedCount.incrementAndGet();
        else deniedCount.incrementAndGet();
    }

    /**
     * Ghi nhận một lần kết nối vào bị chặn và phát cảnh báo nếu phát hiện
     * dấu hiệu thăm dò cổng (nhiều cổng khác nhau trong cửa sổ thời gian ngắn).
     */
    public synchronized void recordDeniedProbe(String srcIp, int targetPort) {
        long now = System.currentTimeMillis();
        Map<Integer, Long> ports = deniedProbes.computeIfAbsent(srcIp, k -> new ConcurrentHashMap<>());
        ports.put(targetPort, now);
        ports.entrySet().removeIf(e -> now - e.getValue() > scanWindowMs);

        if (ports.size() >= scanThreshold) {
            Long last = lastAlert.get(srcIp);
            if (last == null || now - last > scanWindowMs) {
                lastAlert.put(srcIp, now);
                Log.alert("SECURITY", String.format(
                        "Nghi van QUET CONG tu %s: %d cong bi tu choi trong %ds -> %s",
                        srcIp, ports.size(), scanWindowMs / 1000, new ArrayList<>(ports.keySet())));
                if (!"127.0.0.1".equals(srcIp)) {
                    ban(srcIp, 60000, "Quet " + ports.size() + " cong");
                }
            }
        }
    }

    public List<FirewallRule> rules()  { return new ArrayList<>(rules); }

    /** Thêm một luật động lên đầu danh sách để ưu tiên áp dụng ngay lập tức. */
    public synchronized boolean addRule(String ruleText) {
        int nextLine = rules.stream().mapToInt(r -> r.lineNumber).max().orElse(0) + 1;
        FirewallRule r = FirewallRule.parse(ruleText, nextLine);
        if (r == null) return false;
        rules.add(0, r);
        Log.info("FIREWALL", "Da them luat #" + nextLine + ": " + r.raw);
        return true;
    }

    /** Xóa một luật theo số dòng. */
    public synchronized boolean removeRule(int lineNumber) {
        boolean removed = rules.removeIf(r -> r.lineNumber == lineNumber);
        if (removed) {
            Log.info("FIREWALL", "Da xoa luat #" + lineNumber);
        }
        return removed;
    }

    public FirewallRule.Action defaultIn()  { return defaultIn; }
    public FirewallRule.Action defaultOut() { return defaultOut; }
    public long defaultInHits()        { return defaultInHits.get(); }
    public long defaultOutHits()       { return defaultOutHits.get(); }
    public String rulesFile()          { return rulesFile; }
    public long allowedCount()         { return allowedCount.get(); }
    public long deniedCount()          { return deniedCount.get(); }
    public String defaults()           { return "OUT=" + defaultOut + ", IN=" + defaultIn; }

    public Map<String, Integer> probeSummary() {
        Map<String, Integer> out = new HashMap<>();
        deniedProbes.forEach((ip, ports) -> out.put(ip, ports.size()));
        return out;
    }
}
