package nhom06.test;

import nhom06.common.Config;
import nhom06.common.Log;
import nhom06.gateway.NatTable;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * KIỂM THỬ TẢI: đo khả năng xử lý đồng thời của Gateway.
 *
 *  Pha 1 - Thông lượng: N máy LAN (mỗi máy một IP riêng) cùng lúc mở phiên và gửi M thông
 *          điệp; đo độ trễ khứ hồi (RTT) từng thông điệp và thông lượng tổng.
 *  Pha 2 - Cạn tài nguyên: mở đồng thời nhiều phiên hơn số cổng PAT, kiểm chứng Gateway
 *          cấp đúng số cổng có sẵn và từ chối phần dư một cách có kiểm soát.
 *
 * Mặc định tự dựng môi trường riêng (cổng 28xxx/29xxx, dải PAT 100 cổng, log console tắt)
 * nên số liệu sạch, không bị chậm do in ra màn hình.
 *
 *   java -cp out nhom06.test.LoadTest                     (mac dinh: 50 client x 20 thong diep)
 *   java -cp out nhom06.test.LoadTest clients=100 messages=50
 *   java -cp out nhom06.test.LoadTest --live              (chay vao Gateway demo dang mo, xem tren web)
 */
public class LoadTest {

    public static void main(String[] args) throws Exception {
        boolean live = false;
        int clients = 50, messages = 20;
        String server = null;
        for (String a : args) {
            if (a.equals("--live")) live = true;
            else if (a.startsWith("clients=")) clients = Integer.parseInt(a.substring(8));
            else if (a.startsWith("messages=")) messages = Integer.parseInt(a.substring(9));
            else if (a.startsWith("server=")) server = a.substring(7);
        }

        System.out.println("==============================================================");
        System.out.println("   NHOM 06 - KIEM THU TAI GATEWAY NAT/PAT");
        System.out.println("==============================================================");

        TestEnv env;
        String extIp;
        int extTcp;
        NatTable nat = null;
        int capacity;
        if (live) {
            Config cfg = new Config("config/gateway.properties");
            env = TestEnv.attach(cfg);
            String[] sv = (server == null ? "127.0.0.3:9000" : server).split(":");
            extIp = sv[0];
            extTcp = Integer.parseInt(sv[1]);
            capacity = cfg.getInt("nat.port.max", 40099) - cfg.getInt("nat.port.min", 40000) + 1;
            System.out.println("Che do --live: ban vao Gateway dang chay tai " + env.lanIp + ":" + env.lanTcp
                    + ". Nen go 'verbose' o Gateway de tat log chi tiet truoc khi do.");
        } else {
            Properties p = new Properties();
            p.setProperty("gateway.lan.ip", "127.0.0.1");
            p.setProperty("gateway.lan.tcp.port", "28080");
            p.setProperty("gateway.lan.udp.port", "28081");
            p.setProperty("gateway.public.ip", "127.0.0.2");
            p.setProperty("nat.port.min", "42000");
            p.setProperty("nat.port.max", "42099");
            p.setProperty("nat.max.sessions.per.ip", "0");
            p.setProperty("nat.cleanup.interval.ms", "1000");
            p.setProperty("connect.timeout.ms", "5000");
            p.setProperty("log.file", "logs/loadtest.log");
            String rules = "POLICY OUT ALLOW\nPOLICY IN DENY\n";
            extIp = "127.0.0.3";
            extTcp = 29000;
            env = TestEnv.start("loadtest", p, rules, extIp, extTcp, 29001, "127.0.0.4", null, 0);
            nat = env.gw.context().nat;
            capacity = nat.capacity();
            System.out.println("Moi truong rieng: Gateway " + env.lanIp + ":" + env.lanTcp
                    + ", dai PAT 42000-42099 (" + capacity + " cong)");
        }

        StringBuilder rep = new StringBuilder();
        rep.append("NHOM 06 - KET QUA KIEM THU TAI (")
                .append(new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date())).append(")\n");
        rep.append("Che do: ").append(live ? "live (Gateway demo)" : "moi truong rieng").append("\n");
        rep.append("Java ").append(System.getProperty("java.version")).append(", ")
                .append(Runtime.getRuntime().availableProcessors()).append(" CPU, ")
                .append(System.getProperty("os.name")).append("\n\n");

        // ================================================================ PHA 1
        int n = Math.min(clients, capacity);
        System.out.printf("%nPha 1: %d client dong thoi x %d thong diep...%n", n, messages);
        List<Long> rtts = Collections.synchronizedList(new ArrayList<>());
        List<Long> setups = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger sessionsOk = new AtomicInteger(), msgOk = new AtomicInteger(), wrong = new AtomicInteger();
        List<String> errors = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch ready = new CountDownLatch(n), go = new CountDownLatch(1), done = new CountDownLatch(n);
        final TestEnv e1 = env;
        final int msgs = messages;
        for (int i = 0; i < n; i++) {
            final String ip = ipFor(i);
            new Thread(() -> {
                try {
                    ready.countDown();
                    go.await();
                    long t0 = System.nanoTime();
                    TestEnv.Conn c = e1.open(ip, extIp, extTcp);
                    if (!c.ok) throw new IllegalStateException(c.reply);
                    c.readLine();
                    setups.add(System.nanoTime() - t0);
                    sessionsOk.incrementAndGet();
                    for (int j = 0; j < msgs; j++) {
                        String m = ip + "#" + j;
                        long s = System.nanoTime();
                        c.send(m);
                        String r = c.readLine();
                        long d = System.nanoTime() - s;
                        if (r != null && r.endsWith(": " + m)) {
                            rtts.add(d);
                            msgOk.incrementAndGet();
                        } else {
                            wrong.incrementAndGet();
                        }
                    }
                    c.bye();
                } catch (Exception ex) {
                    errors.add(ex.getMessage());
                } finally {
                    done.countDown();
                }
            }).start();
        }
        ready.await();
        long start = System.nanoTime();
        go.countDown();
        done.await();
        double secs = (System.nanoTime() - start) / 1e9;

        List<Long> sorted = new ArrayList<>(rtts);
        Collections.sort(sorted);
        String phase1 = String.format(
                "PHA 1 - THONG LUONG (%d client dong thoi, moi client %d thong diep)%n"
                        + "  Phien mo thanh cong   : %d/%d%n"
                        + "  Thong diep dung       : %d/%d (sai noi dung: %d)%n"
                        + "  Tong thoi gian        : %.2f s%n"
                        + "  Thong luong           : %.0f thong diep/giay%n"
                        + "  Do tre khu hoi (RTT)  : min %.2f ms | TB %.2f ms | p95 %.2f ms | max %.2f ms%n"
                        + "  Thoi gian mo phien TB : %.2f ms%n",
                n, messages, sessionsOk.get(), n, msgOk.get(), n * messages, wrong.get(), secs,
                msgOk.get() / secs, ms(pct(sorted, 0)), ms(avg(sorted)), ms(pct(sorted, 95)),
                ms(pct(sorted, 100)), ms(avg(new ArrayList<>(setups))));
        if (!errors.isEmpty()) phase1 += "  Loi (" + errors.size() + "): " + errors.get(0) + "\n";
        System.out.print(phase1);
        rep.append(phase1).append('\n');

        Thread.sleep(1500);

        // ================================================================ PHA 2
        int k = capacity + 20;
        System.out.printf("%nPha 2: mo dong thoi %d phien (dai PAT chi co %d cong)...%n", k, capacity);
        AtomicInteger okCount = new AtomicInteger(), busy = new AtomicInteger(), other = new AtomicInteger();
        List<TestEnv.Conn> held = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch ready2 = new CountDownLatch(k), go2 = new CountDownLatch(1), done2 = new CountDownLatch(k);
        List<String> otherErr = Collections.synchronizedList(new ArrayList<>());
        for (int i = 0; i < k; i++) {
            final String ip = ipFor(1000 + i);
            new Thread(() -> {
                try {
                    ready2.countDown();
                    go2.await();
                    TestEnv.Conn c = e1.open(ip, extIp, extTcp);
                    if (c.ok) {
                        okCount.incrementAndGet();
                        held.add(c);
                    } else {
                        if (c.reply.contains("Het cong")) busy.incrementAndGet();
                        else {
                            other.incrementAndGet();
                            otherErr.add(c.reply);
                        }
                        c.close();
                    }
                } catch (Exception ex) {
                    other.incrementAndGet();
                    otherErr.add(ex.getMessage());
                } finally {
                    done2.countDown();
                }
            }).start();
        }
        ready2.await();
        long t2 = System.nanoTime();
        go2.countDown();
        done2.await();
        double secs2 = (System.nanoTime() - t2) / 1e9;
        int peak = (nat != null) ? nat.dynamicSize() : -1;
        for (TestEnv.Conn c : new ArrayList<>(held)) c.bye();

        String phase2 = String.format(
                "PHA 2 - CAN DAI CONG PAT (%d yeu cau dong thoi, dai PAT %d cong)%n"
                        + "  Duoc cap cong         : %d%n"
                        + "  Tu choi 'Het cong NAT': %d%n"
                        + "  Loi khac              : %d%n"
                        + "  Thoi gian xu ly       : %.2f s%n"
                        + "%s",
                k, capacity, okCount.get(), busy.get(), other.get(), secs2,
                peak >= 0 ? String.format("  Bang NAT luc day      : %d/%d anh xa%n", peak, capacity) : "");
        if (!otherErr.isEmpty()) phase2 += "  Vi du loi khac: " + otherErr.get(0) + "\n";
        boolean controlled = other.get() == 0 && busy.get() > 0 && okCount.get() + busy.get() == k;
        String verdict;
        if (controlled && live) {
            verdict = "  => DUNG: cap het " + okCount.get() + " cong con trong, tu choi co kiem soat phan du.\n";
        } else if (controlled && okCount.get() == capacity) {
            verdict = "  => DUNG: cap du " + capacity + " cong, tu choi co kiem soat phan du.\n";
        } else {
            verdict = "  => Can xem lai: so phien duoc cap khong khop so cong con trong.\n";
        }
        phase2 += verdict;
        System.out.print(phase2);
        rep.append(phase2);

        Files.createDirectories(Paths.get("logs"));
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(Paths.get("logs", "loadtest-report.txt"),
                StandardCharsets.UTF_8))) {
            w.print(rep);
        }
        System.out.println("\nDa luu bao cao: logs/loadtest-report.txt");
        if (!live) env.gw.stop();
        Log.close();
        System.exit(0);
    }

    /** Mỗi client giả lập một máy LAN riêng: 127.10.x.y */
    private static String ipFor(int i) {
        return "127.10." + (i / 250) + "." + (i % 250 + 1);
    }

    private static long pct(List<Long> sorted, int p) {
        if (sorted.isEmpty()) return 0;
        int idx = (int) Math.ceil(p / 100.0 * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(sorted.size() - 1, idx)));
    }

    private static long avg(List<Long> list) {
        if (list.isEmpty()) return 0;
        long s = 0;
        for (long v : list) s += v;
        return s / list.size();
    }

    private static double ms(long nanos) {
        return nanos / 1e6;
    }
}
