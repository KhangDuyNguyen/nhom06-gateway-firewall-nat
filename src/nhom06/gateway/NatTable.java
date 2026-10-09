package nhom06.gateway;

import nhom06.common.Log;
import nhom06.common.Protocol;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bảng NAT/PAT của Gateway.
 *
 * Toàn bộ cấu trúc dùng ConcurrentHashMap để nhiều luồng xử lý Client có thể
 * tra cứu / ghi nhận song song mà không cần khoá toàn cục (tránh nghẽn cổ chai).
 *
 * Các chỉ mục được duy trì song song:
 *   - byKey           : tra cứu theo chiều đi   (internal [+ đích] -> entry)
 *   - byPublicTcp/Udp : tra cứu theo chiều về  (cổng công khai     -> entry)
 *   - perIp           : số phiên đang mở của từng IP nội bộ (giới hạn tài nguyên)
 *
 * Việc cấp phát cổng dùng putIfAbsent() nên nguyên tử: hai luồng không bao giờ
 * được cấp cùng một cổng công khai.
 */
public class NatTable {

    /** Kết quả cấp phát: thành công (entry != null) hoặc lý do thất bại. */
    public static final class Allocation {
        public final NatEntry entry;
        public final String error;
        public final boolean perIpLimit;

        private Allocation(NatEntry entry, String error, boolean perIpLimit) {
            this.entry = entry;
            this.error = error;
            this.perIpLimit = perIpLimit;
        }

        public boolean ok() {
            return entry != null;
        }
    }

    private final ConcurrentHashMap<String, NatEntry> byKey = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Integer, NatEntry> byPublicTcp = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Integer, NatEntry> byPublicUdp = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicInteger> perIp = new ConcurrentHashMap<>();

    private final String publicIp;
    private final int portMin;
    private final int portMax;
    private final int maxPerIp;
    private final AtomicInteger cursor;
    private volatile NatMode mode;

    private final AtomicLong totalAllocated = new AtomicLong();
    private final AtomicLong totalReleased = new AtomicLong();
    private final AtomicLong totalRejected = new AtomicLong();
    private final AtomicLong limitRejected = new AtomicLong();
    private volatile int peak = 0;

    public NatTable(String publicIp, int portMin, int portMax) {
        this(publicIp, portMin, portMax, 0, NatMode.SYMMETRIC);
    }

    /**
     * @param maxPerIp số phiên tối đa cho mỗi IP nội bộ (0 = không giới hạn)
     */
    public NatTable(String publicIp, int portMin, int portMax, int maxPerIp, NatMode mode) {
        this.publicIp = publicIp;
        this.portMin = portMin;
        this.portMax = portMax;
        this.maxPerIp = maxPerIp;
        this.mode = mode;
        this.cursor = new AtomicInteger(portMin);
    }

    private ConcurrentHashMap<Integer, NatEntry> indexOf(Protocol p) {
        return (p == Protocol.UDP) ? byPublicUdp : byPublicTcp;
    }

    /** Lấy cổng tiếp theo trong dải, quay vòng khi chạm biên. */
    private int nextPort() {
        int size = portMax - portMin + 1;
        int raw = cursor.getAndIncrement();
        if (raw > Integer.MAX_VALUE - 1000) cursor.set(portMin);
        return portMin + Math.floorMod(raw - portMin, size);
    }

    /**
     * Khoá ánh xạ. Với UDP ở các kiểu NAT "cone", khoá KHÔNG chứa đích
     * (Endpoint-Independent Mapping) nên mọi đích dùng chung một cổng công khai.
     */
    private String mapKey(Protocol proto, String iIp, int iPort, String dIp, int dPort) {
        if (proto == Protocol.UDP && !mode.destinationDependentMapping()) {
            return NatEntry.key(proto, iIp, iPort, "*", 0);
        }
        return NatEntry.key(proto, iIp, iPort, dIp, dPort);
    }

    /**
     * Cấp phát một ánh xạ mới.
     * @param exclude cổng vừa thất bại khi bind ở tầng OS, sẽ bị bỏ qua (có thể null)
     */
    public Allocation allocate(Protocol proto, String internalIp, int internalPort,
                               String destIp, int destPort, Integer exclude) {
        // --- 1. Giới hạn số phiên mỗi IP nội bộ (chống một máy chiếm hết cổng NAT) ---
        AtomicInteger count = perIp.computeIfAbsent(internalIp, k -> new AtomicInteger());
        int current = count.incrementAndGet();
        if (maxPerIp > 0 && current > maxPerIp) {
            count.decrementAndGet();
            limitRejected.incrementAndGet();
            Log.fw("NAT-TABLE", "TU CHOI " + internalIp + ":" + internalPort
                    + " - vuot gioi han " + maxPerIp + " phien/IP");
            return new Allocation(null, "Vuot gioi han " + maxPerIp + " phien cho IP " + internalIp, true);
        }

        // --- 2. Tìm cổng công khai còn trống ---
        Map<Integer, NatEntry> index = indexOf(proto);
        NatMode m = mode;
        int attempts = portMax - portMin + 1;

        for (int i = 0; i < attempts; i++) {
            int port = nextPort();
            if (exclude != null && exclude == port) continue;

            NatEntry entry = new NatEntry(proto, internalIp, internalPort,
                    publicIp, port, destIp, destPort, false, m);

            if (index.putIfAbsent(port, entry) == null) {
                entry.mapKey = mapKey(proto, internalIp, internalPort, destIp, destPort);
                entry.countedForIp = true;
                byKey.put(entry.mapKey, entry);
                long nth = totalAllocated.incrementAndGet();
                int cur = size();
                if (cur > peak) peak = cur;
                Log.nat("NAT-TABLE", String.format(
                        "CAP PHAT #%d  %s %s:%d  ->  %s:%d  (dich %s:%d)%s",
                        nth, proto, internalIp, internalPort, publicIp, port, destIp, destPort,
                        proto == Protocol.UDP ? " [" + m.label + "]" : ""));
                return new Allocation(entry, null, false);
            }
        }
        count.decrementAndGet();
        totalRejected.incrementAndGet();
        Log.error("NAT-TABLE", "Het cong trong dai PAT " + portMin + "-" + portMax
                + " -> tu choi phien tu " + internalIp + ":" + internalPort);
        return new Allocation(null, "Het cong NAT (dai " + portMin + "-" + portMax + " da day)", false);
    }

    /** Đăng ký một ánh xạ tĩnh (Port Forwarding). */
    public NatEntry registerStatic(Protocol proto, String internalIp, int internalPort,
                                   int publicPort, String destIp, int destPort) {
        NatEntry entry = new NatEntry(proto, internalIp, internalPort,
                publicIp, publicPort, destIp, destPort, true, mode);
        entry.mapKey = "STATIC|" + proto + "|" + publicPort + "|" + destIp + ":" + destPort + "|" + System.nanoTime();
        byKey.put(entry.mapKey, entry);
        indexOf(proto).put(publicPort, entry);
        return entry;
    }

    public NatEntry lookupOutbound(Protocol proto, String internalIp, int internalPort,
                                   String destIp, int destPort) {
        return byKey.get(mapKey(proto, internalIp, internalPort, destIp, destPort));
    }

    /** Tra cứu chiều về: gói tin quay lại cổng công khai nào thì thuộc Client nào. */
    public NatEntry lookupInbound(Protocol proto, int publicPort) {
        return indexOf(proto).get(publicPort);
    }

    /**
     * Thu hồi ánh xạ. An toàn khi nhiều luồng cùng gọi (NatCleaner + luồng phiên):
     * chỉ luồng thực sự gỡ được entry mới ghi log và cập nhật thống kê.
     */
    public void release(NatEntry entry) {
        if (entry == null) return;
        entry.state(NatEntry.State.CLOSED);
        boolean removed = indexOf(entry.protocol).remove(entry.publicPort, entry);
        if (entry.mapKey != null) byKey.remove(entry.mapKey, entry);
        if (!removed) return;

        if (entry.countedForIp) {
            AtomicInteger c = perIp.get(entry.internalIp);
            if (c != null && c.decrementAndGet() <= 0) perIp.remove(entry.internalIp, c);
        }
        if (entry.staticMapping) return;   // ánh xạ tĩnh không tính vào thống kê PAT

        totalReleased.incrementAndGet();
        Log.nat("NAT-TABLE", String.format(
                "THU HOI     %s %s -> %s  (gui %d B / nhan %d B, song %ds)",
                entry.protocol, entry.internalSocket(), entry.publicSocket(),
                entry.bytesOut(), entry.bytesIn(),
                (System.currentTimeMillis() - entry.createdAt) / 1000));
    }

    public List<NatEntry> snapshot() {
        List<NatEntry> list = new ArrayList<>();
        list.addAll(byPublicTcp.values());
        list.addAll(byPublicUdp.values());
        list.sort(Comparator.comparing((NatEntry e) -> e.protocol).thenComparingInt(e -> e.publicPort));
        return list;
    }

    /** Số phiên đang mở theo từng IP nội bộ. */
    public Map<String, Integer> perIpSnapshot() {
        Map<String, Integer> out = new TreeMap<>();
        perIp.forEach((ip, c) -> {
            if (c.get() > 0) out.put(ip, c.get());
        });
        return out;
    }

    /** Số ánh xạ PAT động đang hoạt động (không tính ánh xạ tĩnh). */
    public int dynamicSize() {
        int n = 0;
        for (NatEntry e : byPublicTcp.values()) if (!e.staticMapping) n++;
        for (NatEntry e : byPublicUdp.values()) if (!e.staticMapping) n++;
        return n;
    }

    public int size()              { return byPublicTcp.size() + byPublicUdp.size(); }
    public int capacity()          { return portMax - portMin + 1; }
    public int portMin()           { return portMin; }
    public int portMax()           { return portMax; }
    public int maxPerIp()          { return maxPerIp; }
    public String publicIp()       { return publicIp; }
    public NatMode mode()          { return mode; }
    public long totalAllocated()   { return totalAllocated.get(); }
    public long totalReleased()    { return totalReleased.get(); }
    public long totalRejected()    { return totalRejected.get(); }
    public long limitRejected()    { return limitRejected.get(); }
    public int peak()              { return peak; }

    /** Đổi kiểu NAT lúc đang chạy. Chỉ áp dụng cho các ánh xạ UDP tạo SAU thời điểm đổi. */
    public void setMode(NatMode m) {
        if (m == null || m == mode) return;
        Log.info("NAT-TABLE", "Doi kieu NAT: " + mode.label + " -> " + m.label
                + " (ap dung cho anh xa UDP moi)");
        mode = m;
    }
}
