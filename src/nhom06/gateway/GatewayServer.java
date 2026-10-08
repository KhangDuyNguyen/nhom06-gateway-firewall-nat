package nhom06.gateway;

import nhom06.common.Config;
import nhom06.common.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * ============================================================================
 *  NHOM 06 - Lap trinh mang
 *  De tai: Xay dung ung dung mo phong Firewall Cong giao tiep (Gateway Firewall)
 *          su dung ky thuat NAT/PAT
 *
 *  GATEWAY: thanh phan trung tam, dong vai tro Router NAT + Tuong lua.
 *    - Lang nghe ket noi TCP/UDP tu mang LAN
 *    - Loc goi tin theo bo luat firewall
 *    - Cap phat va quan ly bang NAT/PAT (ConcurrentHashMap, thread-safe)
 *    - Chuyen tiep du lieu hai chieu, da luong
 *    - Thu hoi phien het han (NAT session timeout)
 *    - NAT tinh (Port Forwarding) + giam sat / canh bao quet cong
 *    - Console quan tri hien thi bang NAT thoi gian thuc
 * ============================================================================
 */
public class GatewayServer {

    private final Config cfg;
    private GatewayContext ctx;
    private ServerSocket lanServer;
    private UdpNatService udp;
    private NatCleaner cleaner;
    private final List<PortForwarder> forwarders = new ArrayList<>();
    private final List<InboundMonitor> monitors = new ArrayList<>();
    private ExecutorService pool;
    private volatile boolean running = true;
    private final long startedAt = System.currentTimeMillis();

    public GatewayServer(Config cfg) {
        this.cfg = cfg;
    }

    public static void main(String[] args) throws Exception {
        String configPath = (args.length > 0) ? args[0] : "config/gateway.properties";
        Config cfg = new Config(configPath);
        Log.init(cfg.get("log.file", "logs/gateway.log"), cfg.getBool("log.verbose", true));
        new GatewayServer(cfg).start();
    }

    public void start() throws Exception {
        String lanIp = cfg.get("gateway.lan.ip", "127.0.0.1");
        int lanTcpPort = cfg.getInt("gateway.lan.tcp.port", 8080);
        int lanUdpPort = cfg.getInt("gateway.lan.udp.port", 8081);
        String publicIp = cfg.get("gateway.public.ip", "127.0.0.2");
        int portMin = cfg.getInt("nat.port.min", 40000);
        int portMax = cfg.getInt("nat.port.max", 40099);

        banner(lanIp, lanTcpPort, lanUdpPort, publicIp, portMin, portMax);

        // Kiem tra kha nang bind IP cong cong; neu he dieu hanh khong cho phep
        // (mot so ban Windows khong dung dia chi 127.0.0.x ngoai 127.0.0.1)
        // thi tu dong lui ve IP LAN de chuong trinh van chay duoc.
        if (!canBind(publicIp)) {
            Log.error("GATEWAY", "Khong bind duoc IP cong cong '" + publicIp
                    + "' -> tu dong dung '" + lanIp + "'. (Van minh hoa duoc PAT qua so hieu cong.)");
            publicIp = lanIp;
        }

        pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });

        NatTable nat = new NatTable(publicIp, portMin, portMax);
        Firewall fw = new Firewall(
                cfg.get("firewall.rules.file", "config/firewall-rules.txt"),
                cfg.getInt("security.scan.threshold", 3),
                cfg.getLong("security.scan.window.ms", 10000));

        ctx = new GatewayContext(nat, fw, lanIp, publicIp, pool,
                cfg.getInt("relay.buffer.size", 8192),
                cfg.getInt("connect.timeout.ms", 5000),
                cfg.getInt("header.timeout.ms", 10000));

        // --- TCP ---
        lanServer = new ServerSocket();
        lanServer.setReuseAddress(true);
        lanServer.bind(new InetSocketAddress(lanIp, lanTcpPort), 100);
        Log.info("GATEWAY", "Lang nghe TCP tai " + lanIp + ":" + lanTcpPort);

        Thread acceptor = new Thread(this::acceptLoop, "lan-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();

        // --- UDP ---
        udp = new UdpNatService(ctx, lanUdpPort, cfg.getInt("relay.buffer.size", 8192));
        udp.start();

        // --- NAT tinh (Port Forwarding) ---
        Map<String, String> pfs = cfg.getByPrefix("portforward.");
        for (Map.Entry<String, String> e : pfs.entrySet()) {
            try {
                PortForwarder pf = PortForwarder.parse(ctx, e.getValue());
                pf.start();
                forwarders.add(pf);
            } catch (Exception ex) {
                Log.error("PORT-FWD", "Bo qua '" + e.getValue() + "': " + ex.getMessage());
            }
        }

        // --- Giam sat cong bi chan ---
        for (int p : cfg.getIntList("monitor.ports", "")) {
            try {
                InboundMonitor m = new InboundMonitor(ctx, p);
                m.start();
                monitors.add(m);
            } catch (IOException ex) {
                Log.error("MONITOR", "Khong mo duoc cong giam sat " + p + ": " + ex.getMessage());
            }
        }
        if (!monitors.isEmpty()) {
            Log.info("MONITOR", "Giam sat cac cong bi chan: " + portList(monitors));
        }

        // --- Don dep bang NAT ---
        cleaner = new NatCleaner(nat,
                cfg.getLong("nat.tcp.timeout.ms", 60000),
                cfg.getLong("nat.udp.timeout.ms", 30000),
                cfg.getLong("nat.cleanup.interval.ms", 5000));
        cleaner.start();

        // --- Tu dong in bang NAT (tuy chon) ---
        long auto = cfg.getLong("nat.autodisplay.ms", 0);
        if (auto > 0) {
            Thread t = new Thread(() -> {
                while (running) {
                    try {
                        Thread.sleep(auto);
                    } catch (InterruptedException e) {
                        return;
                    }
                    printNatTable();
                }
            }, "nat-autodisplay");
            t.setDaemon(true);
            t.start();
        }

        Log.info("GATEWAY", "San sang. Go 'help' de xem cac lenh quan tri.");
        console();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket s = lanServer.accept();
                // Moi ket noi -> mot luong rieng, tranh nghen co chai
                pool.execute(new TcpNatHandler(s, ctx));
            } catch (IOException e) {
                if (running) Log.error("GATEWAY", "Loi accept: " + e.getMessage());
            }
        }
    }

    // ------------------------------------------------------------------
    //  Console quan tri
    // ------------------------------------------------------------------
    private void console() throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while (running && (line = in.readLine()) != null) {
            String[] t = line.trim().split("\\s+");
            String cmd = t[0].toLowerCase();
            switch (cmd) {
                case "":
                    break;
                case "nat":
                    printNatTable();
                    break;
                case "rules":
                    printRules();
                    break;
                case "stats":
                    printStats();
                    break;
                case "alerts":
                    List<String> al = Log.alerts();
                    System.out.println("\n--- CANH BAO AN NINH (" + al.size() + ") ---");
                    al.forEach(System.out::println);
                    System.out.println();
                    break;
                case "log":
                    int n = (t.length > 1) ? Integer.parseInt(t[1]) : 20;
                    System.out.println("\n--- " + n + " DONG NHAT KY GAN NHAT ---");
                    Log.recent(n).forEach(System.out::println);
                    System.out.println();
                    break;
                case "reload":
                    ctx.firewall.load();
                    break;
                case "verbose":
                    Log.setVerbose(!Log.isVerbose());
                    System.out.println("verbose = " + Log.isVerbose());
                    break;
                case "help":
                    printHelp();
                    break;
                case "quit":
                case "exit":
                    shutdown();
                    return;
                default:
                    System.out.println("Lenh khong hop le. Go 'help'.");
            }
        }
    }

    private void printNatTable() {
        List<NatEntry> list = ctx.nat.snapshot();
        StringBuilder sb = new StringBuilder();
        sb.append("\n========================= BANG NAT/PAT =========================\n");
        sb.append(String.format("IP cong cong: %s | Dai cong PAT: %d-%d | Dang dung: %d/%d%n",
                ctx.nat.publicIp(), ctx.nat.portMin(), ctx.nat.portMax(),
                ctx.nat.size(), ctx.nat.capacity()));
        sb.append(String.format("  %-5s %-21s    %-21s    %-21s %7s %8s/%-8s %s%n",
                "PROTO", "NOI BO (LAN)", "CONG CONG (WAN)", "DICH", "IDLE", "GUI", "NHAN", "TT"));
        sb.append("  --------------------------------------------------------------"
                + "---------------------------------------\n");
        if (list.isEmpty()) {
            sb.append("  (bang rong)\n");
        } else {
            for (NatEntry e : list) sb.append("  ").append(e).append("\n");
        }
        sb.append("================================================================\n");
        System.out.println(sb);
    }

    private void printRules() {
        System.out.println("\n--- BO LUAT FIREWALL (khop dau tien thang) ---");
        for (FirewallRule r : ctx.firewall.rules()) System.out.println("  " + r);
        System.out.println("  Mac dinh: " + ctx.firewall.defaults());
        System.out.println();
    }

    private void printStats() {
        long up = (System.currentTimeMillis() - startedAt) / 1000;
        System.out.println("\n--- THONG KE GATEWAY ---");
        System.out.printf("  Thoi gian chay      : %d giay%n", up);
        System.out.printf("  Anh xa dang hoat dong: %d / %d%n", ctx.nat.size(), ctx.nat.capacity());
        System.out.printf("  Tong cap phat        : %d%n", ctx.nat.totalAllocated());
        System.out.printf("  Tong thu hoi         : %d%n", ctx.nat.totalReleased());
        System.out.printf("  Bi tu choi (het cong): %d%n", ctx.nat.totalRejected());
        System.out.printf("  Dinh diem dong thoi  : %d%n", ctx.nat.peak());
        System.out.printf("  Firewall cho phep    : %d%n", ctx.firewall.allowedCount());
        System.out.printf("  Firewall tu choi     : %d%n", ctx.firewall.deniedCount());
        System.out.printf("  IP nghi van tham do  : %s%n", ctx.firewall.probeSummary());
        System.out.println();
    }

    private void printHelp() {
        System.out.println("""

                --- LENH QUAN TRI GATEWAY ---
                  nat        In bang NAT/PAT thoi gian thuc
                  rules      Xem bo luat firewall dang ap dung
                  stats      Thong ke hoat dong
                  alerts     Danh sach canh bao an ninh
                  log [n]    Xem n dong nhat ky gan nhat (mac dinh 20)
                  reload     Nap lai file luat firewall
                  verbose    Bat/tat in chi tiet luong chuyen tiep
                  quit       Dung Gateway
                """);
    }

    private void shutdown() {
        running = false;
        Log.info("GATEWAY", "Dang dung...");
        try {
            if (lanServer != null) lanServer.close();
        } catch (IOException ignored) {
        }
        if (udp != null) udp.stop();
        if (cleaner != null) cleaner.stop();
        forwarders.forEach(PortForwarder::stop);
        monitors.forEach(InboundMonitor::stop);
        if (pool != null) {
            pool.shutdownNow();
            try {
                pool.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
            }
        }
        Log.info("GATEWAY", "Da dung.");
        Log.close();
    }

    private static boolean canBind(String ip) {
        try (ServerSocket s = new ServerSocket()) {
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress(ip, 0));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String portList(List<InboundMonitor> ms) {
        StringBuilder sb = new StringBuilder();
        for (InboundMonitor m : ms) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(m.port());
        }
        return sb.toString();
    }

    private void banner(String lanIp, int tcp, int udpPort, String pub, int min, int max) {
        System.out.println("""
                ==============================================================
                   NHOM 06 - MO PHONG GATEWAY FIREWALL NAT/PAT
                   Client (LAN)  <-->  GATEWAY (NAT + Firewall)  <-->  Internet
                ==============================================================""");
        System.out.printf("  Giao dien LAN   : %s (TCP %d, UDP %d)%n", lanIp, tcp, udpPort);
        System.out.printf("  Giao dien WAN   : %s (dai cong PAT %d-%d)%n", pub, min, max);
        System.out.println("--------------------------------------------------------------");
    }
}
