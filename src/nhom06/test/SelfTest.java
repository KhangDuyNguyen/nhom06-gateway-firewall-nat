package nhom06.test;

import nhom06.common.Log;
import nhom06.common.Protocol;
import nhom06.gateway.FirewallRule;
import nhom06.gateway.NatEntry;
import nhom06.gateway.NatMode;
import nhom06.gateway.NatTable;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * BỘ TỰ KIỂM THỬ: một lệnh chạy toàn bộ kịch bản và in PASS/FAIL.
 *
 * Tự dựng môi trường riêng trong cùng tiến trình (cổng 18xxx/19xxx, dải PAT 41000-41009)
 * nên KHÔNG cần mở trước các cửa sổ demo và chạy được song song với bản demo.
 *
 * Chạy:  java -cp out nhom06.test.SelfTest
 * Kết quả cũng được ghi vào logs/selftest-report.txt để đưa vào báo cáo.
 */
public class SelfTest {

    private static final String EXT = "127.0.0.3";
    private static final int EXT_TCP = 19000;
    private static final int EXT_UDP = 19001;
    private static final String PEER = "127.0.0.4";

    private interface Check {
        String run() throws Exception;
    }

    private static final List<String[]> results = new ArrayList<>();
    private static int pass = 0, fail = 0, skip = 0;
    private static TestEnv env;

    public static void main(String[] args) throws Exception {
        System.out.println("==============================================================");
        System.out.println("   NHOM 06 - BO TU KIEM THU GATEWAY FIREWALL NAT/PAT");
        System.out.println("==============================================================");
        System.out.println("Dang dung moi truong kiem thu (cong 18xxx/19xxx, dai PAT 41000-41009)...");

        Properties p = new Properties();
        p.setProperty("gateway.lan.ip", "127.0.0.1");
        p.setProperty("gateway.lan.tcp.port", "18080");
        p.setProperty("gateway.lan.udp.port", "18081");
        p.setProperty("gateway.public.ip", "127.0.0.2");
        p.setProperty("nat.port.min", "41000");
        p.setProperty("nat.port.max", "41009");
        p.setProperty("nat.max.sessions.per.ip", "6");
        p.setProperty("nat.mode", "SYMMETRIC");
        p.setProperty("nat.tcp.timeout.ms", "60000");
        p.setProperty("nat.udp.timeout.ms", "2000");
        p.setProperty("nat.tcp.transitory.timeout.ms", "3000");
        p.setProperty("nat.cleanup.interval.ms", "500");
        p.setProperty("security.scan.threshold", "3");
        p.setProperty("security.scan.window.ms", "10000");
        p.setProperty("monitor.ports", "18023,18445,18139");
        p.setProperty("portforward.1", "18090>127.0.0.20:17000");
        p.setProperty("connect.timeout.ms", "3000");
        p.setProperty("header.timeout.ms", "5000");
        p.setProperty("log.file", "logs/selftest.log");

        String rules = String.join("\n",
                "DENY  OUT TCP *           * *         23",
                "ALLOW OUT *   127.0.0.0/8 * 127.0.0.3 *",
                "ALLOW OUT *   127.0.0.0/8 * 127.0.0.4 *",
                "ALLOW IN  TCP *           * *         18090",
                "POLICY OUT ALLOW",
                "POLICY IN  DENY", "");

        env = TestEnv.start("selftest", p, rules, EXT, EXT_TCP, EXT_UDP, PEER, "127.0.0.20", 17000);
        System.out.println("IP cong cong cua Gateway: " + env.publicIp + "\n");
        NatTable nat = env.gw.context().nat;

        // ============================================================ NAT / PAT
        test("T01", "NAT che giau IP noi bo (TCP)", () -> {
            TestEnv.Conn c = env.open("127.0.0.11", EXT, EXT_TCP);
            expect(c.ok, "Gateway tu choi: " + c.reply);
            String seen = TestEnv.seenAddress(c.readLine());
            c.bye();
            expect(seen != null && seen.equals(c.publicAddr), "Server thay " + seen + ", mong doi " + c.publicAddr);
            expect(!seen.startsWith("127.0.0.11:"), "Lo IP noi bo ra ngoai");
            return "127.0.0.11 -> server chi thay " + seen;
        });

        test("T02", "PAT: 3 phien cung IP -> 3 cong cong khai", () -> {
            List<TestEnv.Conn> cs = new ArrayList<>();
            Set<String> pubs = new HashSet<>();
            for (int i = 0; i < 3; i++) {
                TestEnv.Conn c = env.open("127.0.0.11", EXT, EXT_TCP);
                expect(c.ok, "Phien " + (i + 1) + " bi tu choi: " + c.reply);
                cs.add(c);
                pubs.add(c.publicAddr);
            }
            cs.forEach(TestEnv.Conn::bye);
            expect(pubs.size() == 3, "Chi co " + pubs.size() + " cong khac nhau: " + pubs);
            return "Cong cong khai: " + pubs;
        });

        test("T03", "Firewall chan chieu ra (Telnet cong 23)", () -> {
            TestEnv.Conn c = env.open("127.0.0.11", EXT, 23);
            c.close();
            expect(!c.ok && c.reply.contains("403"), "Khong bi chan, Gateway tra loi: " + c.reply);
            return c.reply.replace("NAT/1.0 ", "");
        });

        test("T04", "Da luong: 8 phien dong thoi, du lieu khong lan nhau", () -> {
            int n = 8, msgs = 20;
            AtomicInteger good = new AtomicInteger();
            List<String> errors = new ArrayList<>();
            CountDownLatch done = new CountDownLatch(n);
            for (int i = 0; i < n; i++) {
                final int k = i;
                new Thread(() -> {
                    try {
                        TestEnv.Conn c = env.open("127.0.0.3" + (k + 1), EXT, EXT_TCP);
                        if (!c.ok) throw new IllegalStateException(c.reply);
                        c.readLine();
                        for (int j = 0; j < msgs; j++) {
                            String m = "client" + k + "-msg" + j;
                            c.send(m);
                            String r = c.readLine();
                            if (r == null || !r.endsWith(": " + m)) throw new IllegalStateException("Sai echo: " + r);
                            if (!c.publicAddr.equals(TestEnv.seenAddress(r)))
                                throw new IllegalStateException("Sai dia chi nguon: " + r);
                        }
                        c.bye();
                        good.incrementAndGet();
                    } catch (Exception e) {
                        synchronized (errors) {
                            errors.add(e.getMessage());
                        }
                    } finally {
                        done.countDown();
                    }
                }).start();
            }
            done.await();
            expect(good.get() == n, good.get() + "/" + n + " phien dung. Loi: " + errors);
            return n + " phien x " + msgs + " thong diep, tat ca dung nguoi nhan";
        });

        // ============================================================ UDP + KIỂU NAT
        test("T05", "UDP PAT co ban", () -> {
            TestEnv.Udp u = env.udp("127.0.0.12");
            u.send(EXT, EXT_UDP, "hello");
            List<TestEnv.Msg> r = u.receive(1500);
            u.close();
            TestEnv.Msg echo = find(r, EXT + ":" + EXT_UDP);
            expect(echo != null, "Khong nhan duoc phan hoi UDP: " + r);
            String seen = TestEnv.seenAddress(echo.body);
            expect(seen != null && seen.startsWith(env.publicIp + ":"), "Server thay " + seen);
            return "Server UDP thay " + seen;
        });

        test("T06", "Symmetric: moi dich mot anh xa rieng", () -> {
            TestEnv.Udp u = env.udp("127.0.0.13");
            String p1 = udpSeen(u, EXT_UDP);
            String p2 = udpSeen(u, EXT_UDP + 1);
            u.close();
            expect(p1 != null && p2 != null, "Thieu phan hoi");
            expect(!p1.equals(p2), "Hai dich dung chung " + p1);
            return "Dich :" + EXT_UDP + " -> " + p1 + ", dich :" + (EXT_UDP + 1) + " -> " + p2;
        });

        test("T07", "Symmetric: chan goi tu ben thu ba", () -> {
            TestEnv.Udp u = env.udp("127.0.0.14");
            u.send(EXT, EXT_UDP, "peer");
            List<TestEnv.Msg> r = u.receive(1200);
            u.close();
            expect(find(r, EXT + ":" + EXT_UDP) != null, "Khong nhan duoc echo");
            expect(find(r, EXT + ":" + (EXT_UDP + 1)) == null && find(r, PEER + ":") == null,
                    "Goi ben thu ba lot vao: " + r);
            return "Chi nhan echo; goi tu " + EXT + ":" + (EXT_UDP + 1) + " va " + PEER + " bi chan";
        });

        test("T08", "Full-cone: dung chung anh xa + nhan tu moi nguon", () -> {
            nat.setMode(NatMode.FULL_CONE);
            TestEnv.Udp u = env.udp("127.0.0.15");
            String p1 = udpSeen(u, EXT_UDP);
            String p2 = udpSeen(u, EXT_UDP + 1);
            u.close();
            expect(p1 != null && p1.equals(p2), "Anh xa khac nhau: " + p1 + " / " + p2);
            TestEnv.Udp v = env.udp("127.0.0.16");
            v.send(EXT, EXT_UDP, "peer");
            List<TestEnv.Msg> r = v.receive(1200);
            v.close();
            expect(find(r, EXT + ":" + (EXT_UDP + 1)) != null, "Khong nhan duoc goi cung IP khac cong: " + r);
            if (env.peerOtherIpAvailable) {
                expect(find(r, PEER + ":") != null, "Khong nhan duoc goi tu IP khac: " + r);
            }
            return "Hai dich chung " + p1 + "; nhan duoc goi tu ben thu ba"
                    + (env.peerOtherIpAvailable ? " (ca khac IP)" : "");
        });

        test("T09", "Restricted-cone: chi nhan tu IP da lien lac", () -> {
            nat.setMode(NatMode.RESTRICTED_CONE);
            TestEnv.Udp u = env.udp("127.0.0.17");
            u.send(EXT, EXT_UDP, "peer");
            List<TestEnv.Msg> r = u.receive(1200);
            u.close();
            expect(find(r, EXT + ":" + (EXT_UDP + 1)) != null, "Goi cung IP bi chan nham: " + r);
            if (env.peerOtherIpAvailable) {
                expect(find(r, PEER + ":") == null, "Goi tu IP la lot vao: " + r);
            }
            return "Cung IP (khac cong): qua; khac IP: bi chan";
        });

        test("T10", "Port-restricted-cone: chung anh xa, loc dung (IP,cong)", () -> {
            nat.setMode(NatMode.PORT_RESTRICTED_CONE);
            TestEnv.Udp u = env.udp("127.0.0.18");
            u.send(EXT, EXT_UDP, "peer");
            List<TestEnv.Msg> r = u.receive(1200);
            TestEnv.Msg echo = find(r, EXT + ":" + EXT_UDP);
            String p1 = echo == null ? null : TestEnv.seenAddress(echo.body);
            String p2 = udpSeen(u, EXT_UDP + 1);
            u.close();
            nat.setMode(NatMode.SYMMETRIC);
            expect(echo != null, "Khong nhan duoc echo");
            expect(find(r, EXT + ":" + (EXT_UDP + 1)) == null && find(r, PEER + ":") == null,
                    "Goi ben thu ba lot vao: " + r);
            expect(p1 != null && p1.equals(p2), "Anh xa khac nhau: " + p1 + " / " + p2);
            return "Chung anh xa " + p1 + "; moi goi ben thu ba bi chan";
        });

        // ============================================================ PORT FORWARDING / AN NINH
        test("T11", "Port Forwarding (NAT tinh) vao dich vu LAN", () -> {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(env.publicIp, 18090), 3000);
                s.setSoTimeout(3000);
                BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                String banner = in.readLine();
                expect(banner != null && banner.contains("[LAN-SERVICE]"), "Khong vao duoc dich vu noi bo: " + banner);
                return env.publicIp + ":18090 -> 127.0.0.20:17000 OK";
            }
        });

        test("T12", "Canh bao quet cong (3 cong song song -> dung 1 canh bao)", () -> {
            long before = Log.alertTotal();
            int[] ports = {18023, 18445, 18139};
            CountDownLatch done = new CountDownLatch(ports.length);
            for (int port : ports) {
                new Thread(() -> {
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress(env.publicIp, port), 1500);
                    } catch (Exception ignored) {
                    } finally {
                        done.countDown();
                    }
                }).start();
            }
            done.await();
            Thread.sleep(600);
            long n = Log.alertTotal() - before;
            expect(n == 1, "So canh bao: " + n + " (mong doi 1)");
            return "Phat dung 1 canh bao QUET CONG";
        });

        // ============================================================ GIỚI HẠN TÀI NGUYÊN
        waitTcpEmpty(nat, 6000);

        test("T13", "Gioi han 6 phien moi IP noi bo", () -> {
            List<TestEnv.Conn> keep = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                TestEnv.Conn c = env.open("127.0.0.41", EXT, EXT_TCP);
                expect(c.ok, "Phien " + (i + 1) + " bi tu choi: " + c.reply);
                keep.add(c);
            }
            TestEnv.Conn extra = env.open("127.0.0.41", EXT, EXT_TCP);
            extra.close();
            held.addAll(keep);
            expect(!extra.ok && extra.reply.contains("gioi han"), "Phien thu 7 khong bi chan: " + extra.reply);
            return "Phien thu 7: " + extra.reply.replace("NAT/1.0 ", "");
        });

        test("T14", "Can dai cong PAT (10 cong) -> tu choi", () -> {
            for (int i = 0; i < 4; i++) {
                TestEnv.Conn c = env.open("127.0.0.42", EXT, EXT_TCP);
                expect(c.ok, "Phien " + (i + 1) + "/4 bi tu choi som: " + c.reply);
                held.add(c);
            }
            TestEnv.Conn extra = env.open("127.0.0.43", EXT, EXT_TCP);
            extra.close();
            expect(!extra.ok && extra.reply.contains("Het cong"), "Khong bao het cong: " + extra.reply);
            return "Phien thu 11: " + extra.reply.replace("NAT/1.0 ", "");
        });
        held.forEach(TestEnv.Conn::bye);
        held.clear();

        // ============================================================ TRẠNG THÁI / TIMEOUT
        test("T15", "TCP half-close: gui FIN van nhan duoc du lieu", () -> {
            TestEnv.Conn c = env.open("127.0.0.51", EXT, EXT_TCP);
            expect(c.ok, "Bi tu choi: " + c.reply);
            c.readLine();
            c.socket.shutdownOutput();
            String last = c.readLine();
            String eof = c.readLine();
            c.close();
            expect(last != null && last.contains("Da nhan FIN"), "Khong nhan duoc dong cuoi: " + last);
            expect(eof == null, "Khong nhan duoc FIN tu server");
            Thread.sleep(200);
            boolean logged = Log.recent(400).stream()
                    .anyMatch(l -> l.contains("TCP 127.0.0.51") && l.contains("FIN tu LAN"));
            expect(logged, "Gateway khong ghi nhan FIN tu LAN");
            return "FIN tu LAN -> van nhan duoc dong cuoi -> FIN tu server";
        });

        test("T16", "NAT timeout: anh xa UDP tu thu hoi", () -> {
            TestEnv.Udp u = env.udp("127.0.0.52");
            u.send(EXT, EXT_UDP, "hello");
            u.receive(800);
            boolean present = hasMapping(nat, "127.0.0.52");
            Thread.sleep(2000 + 500 + 900);
            boolean after = hasMapping(nat, "127.0.0.52");
            u.close();
            expect(present, "Khong thay anh xa sau khi gui");
            expect(!after, "Anh xa van con sau timeout");
            return "Anh xa bien mat sau ~2.5 giay im lang";
        });

        waitTcpEmpty(nat, 6000);
        Thread.sleep(2600);   // cho cac anh xa UDP con lai het han

        test("T17", "Thong ke nhat quan + dem luot khop luat", () -> {
            long alloc = nat.totalAllocated(), rel = nat.totalReleased();
            int active = nat.dynamicSize();
            expect(alloc == rel + active,
                    "Cap phat " + alloc + " != thu hoi " + rel + " + dang mo " + active);
            long telnetHits = 0;
            for (FirewallRule r : env.gw.context().firewall.rules()) {
                if ("23".equals(r.dstPortSpec)) telnetHits = r.hits();
            }
            expect(telnetHits >= 1, "Luat chan Telnet chua tung khop");
            return "Cap phat " + alloc + " = thu hoi " + rel + " + dang mo " + active
                    + "; luat Telnet khop " + telnetHits + " lan";
        });

        report();
        env.gw.stop();
        System.exit(fail == 0 ? 0 : 1);
    }

    private static final List<TestEnv.Conn> held = new ArrayList<>();

    // ------------------------------------------------------------------ tiện ích
    private static void test(String id, String name, Check c) {
        long t0 = System.currentTimeMillis();
        String status, detail;
        try {
            detail = c.run();
            status = "PASS";
            pass++;
        } catch (Throwable t) {
            detail = String.valueOf(t.getMessage());
            status = "FAIL";
            fail++;
        }
        long ms = System.currentTimeMillis() - t0;
        results.add(new String[]{id, name, status, ms + " ms", detail});
        System.out.printf("[%s] %-4s %-55s (%d ms)%n       %s%n", status, id, name, ms, detail);
    }

    private static void expect(boolean cond, String msg) {
        if (!cond) throw new AssertionError(msg);
    }

    private static TestEnv.Msg find(List<TestEnv.Msg> list, String fromPrefix) {
        for (TestEnv.Msg m : list) if (m.from.startsWith(fromPrefix)) return m;
        return null;
    }

    private static String udpSeen(TestEnv.Udp u, int port) throws Exception {
        u.send(EXT, port, "probe");
        for (TestEnv.Msg m : u.receive(1200)) {
            if (m.from.equals(EXT + ":" + port)) return TestEnv.seenAddress(m.body);
        }
        return null;
    }

    private static boolean hasMapping(NatTable nat, String ip) {
        for (NatEntry e : nat.snapshot()) if (e.internalIp.equals(ip)) return true;
        return false;
    }

    private static void waitTcpEmpty(NatTable nat, long maxMs) throws InterruptedException {
        long end = System.currentTimeMillis() + maxMs;
        while (System.currentTimeMillis() < end) {
            boolean any = false;
            for (NatEntry e : nat.snapshot()) {
                if (e.protocol == Protocol.TCP && !e.staticMapping) {
                    any = true;
                    break;
                }
            }
            if (!any) return;
            Thread.sleep(100);
        }
    }

    private static void report() throws Exception {
        String line = "--------------------------------------------------------------------------------";
        StringBuilder sb = new StringBuilder();
        sb.append("NHOM 06 - KET QUA TU KIEM THU (").append(new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()))
                .append(")\n").append(line).append('\n');
        sb.append(String.format("%-4s %-55s %-5s %8s%n", "ID", "KICH BAN", "KQ", "TG"));
        sb.append(line).append('\n');
        for (String[] r : results) {
            sb.append(String.format("%-4s %-55s %-5s %8s%n", r[0], r[1], r[2], r[3]));
            sb.append("     ").append(r[4]).append('\n');
        }
        sb.append(line).append('\n');
        sb.append(String.format("TONG: %d/%d PASS, %d FAIL%n", pass, pass + fail, fail));
        System.out.println("\n" + sb);
        Files.createDirectories(Paths.get("logs"));
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(Paths.get("logs", "selftest-report.txt"),
                StandardCharsets.UTF_8))) {
            w.print(sb);
        }
        System.out.println("Da luu bao cao: logs/selftest-report.txt");
    }
}
