package nhom06.gateway;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import nhom06.common.Config;
import nhom06.common.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Web dashboard chạy ngay trong tiến trình Gateway (dùng com.sun.net.httpserver có sẵn
 * trong JDK, không cần thư viện ngoài).
 *
 *   GET  /            trang giao diện (web/index.html)
 *   GET  /api/state   toàn bộ trạng thái Gateway dạng JSON (trang web hỏi mỗi giây)
 *   POST /api/action  thao tác demo: mở phiên, gửi UDP, quét cổng, đổi kiểu NAT...
 *
 * Chỉ lắng nghe trên 127.0.0.1 nên chỉ máy đang chạy demo mới truy cập được.
 */
public class WebDashboard {

    private final GatewayServer gw;
    private final String ip;
    private final int port;
    private final Path indexFile;
    private final DemoClient demo;
    private final String demoServerIp;
    private final int demoTcp;
    private final int demoUdp;
    private HttpServer server;

    public WebDashboard(GatewayServer gw, String ip, int port, String webDir) {
        this.gw = gw;
        this.ip = ip;
        this.port = port;
        this.indexFile = Paths.get(webDir, "index.html");
        GatewayContext ctx = gw.context();
        this.demo = new DemoClient(ctx.lanIp, gw.lanTcpPort(), gw.lanUdpPort());
        Config cfg = gw.config();
        this.demoServerIp = cfg.get("web.demo.server.ip", "127.0.0.3");
        this.demoTcp = cfg.getInt("web.demo.server.tcp", 9000);
        this.demoUdp = cfg.getInt("web.demo.server.udp", 9001);
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(ip, port), 50);
        server.createContext("/", this::handleStatic);
        server.createContext("/api/state", this::handleState);
        server.createContext("/api/action", this::handleAction);
        server.setExecutor(Executors.newFixedThreadPool(6, r -> {
            Thread t = new Thread(r, "web");
            t.setDaemon(true);
            return t;
        }));
        server.start();
    }

    public String url() {
        return "http://" + ip + ":" + port;
    }

    public void stop() {
        demo.shutdown();
        if (server != null) server.stop(0);
    }

    // ------------------------------------------------------------------ trang tĩnh
    private void handleStatic(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        if (!path.equals("/") && !path.equals("/index.html")) {
            send(ex, 404, "text/plain; charset=utf-8", "Khong tim thay".getBytes(StandardCharsets.UTF_8));
            return;
        }
        byte[] body;
        if (Files.exists(indexFile)) {
            body = Files.readAllBytes(indexFile);
        } else {
            body = ("<!doctype html><meta charset=utf-8><title>Thieu giao dien</title>"
                    + "<p>Khong tim thay file <b>" + indexFile.toAbsolutePath() + "</b>. "
                    + "Hay chay Gateway tu thu muc goc cua du an.</p>").getBytes(StandardCharsets.UTF_8);
        }
        send(ex, 200, "text/html; charset=utf-8", body);
    }

    // ------------------------------------------------------------------ trạng thái
    private void handleState(HttpExchange ex) throws IOException {
        try {
            send(ex, 200, "application/json; charset=utf-8", stateJson().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            send(ex, 500, "application/json; charset=utf-8",
                    ("{\"error\":" + q(String.valueOf(e)) + "}").getBytes(StandardCharsets.UTF_8));
        }
    }

    private String stateJson() {
        GatewayContext ctx = gw.context();
        NatTable nat = ctx.nat;
        Firewall fw = ctx.firewall;
        NatCleaner cl = gw.cleaner();
        long now = System.currentTimeMillis();
        StringBuilder b = new StringBuilder(16384);

        b.append("{\"now\":").append(now);

        // --- cấu hình gateway ---
        b.append(",\"gateway\":{")
                .append("\"lanIp\":").append(q(ctx.lanIp))
                .append(",\"lanTcpPort\":").append(gw.lanTcpPort())
                .append(",\"lanUdpPort\":").append(gw.lanUdpPort())
                .append(",\"publicIp\":").append(q(ctx.publicIp))
                .append(",\"portMin\":").append(nat.portMin())
                .append(",\"portMax\":").append(nat.portMax())
                .append(",\"capacity\":").append(nat.capacity())
                .append(",\"maxPerIp\":").append(nat.maxPerIp())
                .append(",\"mode\":").append(q(nat.mode().name()))
                .append(",\"tcpTimeout\":").append(cl.tcpTimeoutMs())
                .append(",\"udpTimeout\":").append(cl.udpTimeoutMs())
                .append(",\"transTimeout\":").append(cl.transitoryTimeoutMs())
                .append(",\"uptime\":").append(now - gw.startedAt())
                .append(",\"verbose\":").append(Log.isVerbose())
                .append(",\"demoServer\":{\"ip\":").append(q(demoServerIp))
                .append(",\"tcp\":").append(demoTcp).append(",\"udp\":").append(demoUdp).append("}");
        b.append(",\"modes\":[");
        NatMode[] modes = NatMode.values();
        for (int i = 0; i < modes.length; i++) {
            if (i > 0) b.append(',');
            b.append("{\"name\":").append(q(modes[i].name()))
                    .append(",\"label\":").append(q(modes[i].label))
                    .append(",\"description\":").append(q(modes[i].description)).append('}');
        }
        b.append("],\"forwards\":[");
        List<PortForwarder> fws = gw.forwarders();
        for (int i = 0; i < fws.size(); i++) {
            if (i > 0) b.append(',');
            b.append("{\"publicPort\":").append(fws.get(i).publicPort())
                    .append(",\"target\":").append(q(fws.get(i).internalTarget())).append('}');
        }
        b.append("],\"monitorPorts\":").append(gw.monitorPorts().toString());
        b.append("}");

        // --- thống kê ---
        b.append(",\"stats\":{")
                .append("\"active\":").append(nat.dynamicSize())
                .append(",\"allocated\":").append(nat.totalAllocated())
                .append(",\"released\":").append(nat.totalReleased())
                .append(",\"rejected\":").append(nat.totalRejected())
                .append(",\"limitRejected\":").append(nat.limitRejected())
                .append(",\"peak\":").append(nat.peak())
                .append(",\"fwAllowed\":").append(fw.allowedCount())
                .append(",\"fwDenied\":").append(fw.deniedCount())
                .append(",\"alerts\":").append(Log.alertTotal())
                .append(",\"bytesIn\":").append(nat.totalBytesIn())
                .append(",\"bytesOut\":").append(nat.totalBytesOut())
                .append("}");

        // --- bảng NAT ---
        b.append(",\"nat\":[");
        boolean first = true;
        for (NatEntry e : nat.snapshot()) {
            if (!first) b.append(',');
            first = false;
            b.append("{\"proto\":").append(q(e.protocol.name()))
                    .append(",\"internal\":").append(q(e.internalSocket()))
                    .append(",\"internalIp\":").append(q(e.internalIp))
                    .append(",\"public\":").append(q(e.publicSocket()))
                    .append(",\"publicPort\":").append(e.publicPort)
                    .append(",\"dest\":").append(q(e.destSocket()))
                    .append(",\"peers\":").append(e.peerCount())
                    .append(",\"state\":").append(q(e.state().name()))
                    .append(",\"idle\":").append(e.idleMillis())
                    .append(",\"limit\":").append(e.staticMapping ? 0 : cl.limitFor(e))
                    .append(",\"age\":").append(now - e.createdAt)
                    .append(",\"out\":").append(e.bytesOut())
                    .append(",\"in\":").append(e.bytesIn())
                    .append(",\"static\":").append(e.staticMapping)
                    .append(",\"mode\":").append(q(e.mode.label))
                    .append('}');
        }
        b.append("]");

        // --- số phiên theo IP ---
        b.append(",\"perIp\":{");
        first = true;
        for (Map.Entry<String, Integer> en : nat.perIpSnapshot().entrySet()) {
            if (!first) b.append(',');
            first = false;
            b.append(q(en.getKey())).append(':').append(en.getValue());
        }
        b.append("}");

        // --- luật firewall ---
        b.append(",\"rules\":[");
        first = true;
        for (FirewallRule r : fw.rules()) {
            if (!first) b.append(',');
            first = false;
            b.append("{\"line\":").append(r.lineNumber)
                    .append(",\"action\":").append(q(r.action.name()))
                    .append(",\"dir\":").append(q(r.direction.name()))
                    .append(",\"proto\":").append(q(r.protocol.name()))
                    .append(",\"src\":").append(q(r.srcIpSpec + ":" + r.srcPortSpec))
                    .append(",\"dst\":").append(q(r.dstIpSpec + ":" + r.dstPortSpec))
                    .append(",\"hits\":").append(r.hits())
                    .append('}');
        }
        b.append("],\"defaults\":{\"out\":").append(q(fw.defaultOut().name()))
                .append(",\"in\":").append(q(fw.defaultIn().name()))
                .append(",\"outHits\":").append(fw.defaultOutHits())
                .append(",\"inHits\":").append(fw.defaultInHits()).append("}");

        // --- cảnh báo, thăm dò, nhật ký ---
        b.append(",\"alerts\":").append(strArray(Log.alerts()));
        b.append(",\"probes\":{");
        first = true;
        for (Map.Entry<String, Integer> en : fw.probeSummary().entrySet()) {
            if (!first) b.append(',');
            first = false;
            b.append(q(en.getKey())).append(':').append(en.getValue());
        }
        b.append("}");
        b.append(",\"log\":").append(strArray(Log.recent(150)));

        // --- phiên demo ---
        b.append(",\"demo\":{\"sessions\":[");
        first = true;
        for (DemoClient.Session s : demo.sessions()) {
            if (!first) b.append(',');
            first = false;
            b.append("{\"id\":").append(s.id)
                    .append(",\"src\":").append(q(s.srcIp + ":" + s.localPort))
                    .append(",\"public\":").append(q(s.publicAddr))
                    .append(",\"dest\":").append(q(s.destIp + ":" + s.destPort))
                    .append(",\"status\":").append(q(s.status()))
                    .append(",\"lines\":").append(strArray(s.lines()))
                    .append('}');
        }
        b.append("],\"udp\":[");
        first = true;
        for (DemoClient.UdpEvent u : demo.udpEvents()) {
            if (!first) b.append(',');
            first = false;
            b.append("{\"time\":").append(q(u.time))
                    .append(",\"host\":").append(q(u.host))
                    .append(",\"peer\":").append(q(u.peer))
                    .append(",\"out\":").append(u.outgoing)
                    .append(",\"text\":").append(q(u.text))
                    .append('}');
        }
        b.append("]}");

        // --- lịch sử phiên đã kết thúc ---
        b.append(",\"history\":[");
        first = true;
        for (NatTable.HistoryEntry h : nat.history()) {
            if (!first) b.append(',');
            first = false;
            b.append("{\"proto\":").append(q(h.proto))
                    .append(",\"internal\":").append(q(h.internal))
                    .append(",\"public\":").append(q(h.pub))
                    .append(",\"dest\":").append(q(h.dest))
                    .append(",\"out\":").append(h.bytesOut)
                    .append(",\"in\":").append(h.bytesIn)
                    .append(",\"duration\":").append(h.durationSec)
                    .append(",\"state\":").append(q(h.state))
                    .append(",\"closedAt\":").append(h.closedAt)
                    .append('}');
        }
        b.append(']');

        // --- danh sách IP bị cấm (Auto-ban) ---
        b.append(",\"banned\":{");
        first = true;
        for (Map.Entry<String, String> be : fw.bannedIpsSummary().entrySet()) {
            if (!first) b.append(',');
            first = false;
            b.append(q(be.getKey())).append(':').append(q(be.getValue()));
        }
        b.append('}');

        // --- cấu hình QoS ---
        b.append(",\"qos\":{");
        first = true;
        for (Map.Entry<String, Integer> qe : ctx.qosLimitsKb().entrySet()) {
            if (!first) b.append(',');
            first = false;
            b.append(q(qe.getKey())).append(':').append(qe.getValue());
        }
        b.append('}');

        b.append('}');
        return b.toString();
    }

    // ------------------------------------------------------------------ thao tác
    private void handleAction(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json; charset=utf-8",
                    "{\"ok\":false,\"message\":\"Chi chap nhan POST\"}".getBytes(StandardCharsets.UTF_8));
            return;
        }
        Map<String, String> p = params(ex.getRequestURI().getRawQuery());
        p.putAll(params(readBody(ex.getRequestBody())));
        DemoClient.Result r;
        try {
            r = perform(p);
        } catch (Exception e) {
            r = new DemoClient.Result(false, "Loi: " + e.getMessage());
        }
        String json = "{\"ok\":" + r.ok + ",\"message\":" + q(r.message) + "}";
        send(ex, 200, "application/json; charset=utf-8", json.getBytes(StandardCharsets.UTF_8));
    }

    private DemoClient.Result perform(Map<String, String> p) {
        GatewayContext ctx = gw.context();
        String type = p.getOrDefault("type", "");
        String src = p.getOrDefault("src", "127.0.0.11");
        String dst = p.getOrDefault("dst", demoServerIp);
        switch (type) {
            case "open":
                return demo.open(src, dst, intOf(p.get("port"), demoTcp));
            case "multi": {
                int n = Math.max(1, Math.min(20, intOf(p.get("n"), 3)));
                int ok = 0;
                String last = "";
                for (int i = 0; i < n; i++) {
                    DemoClient.Result r = demo.open(src, dst, intOf(p.get("port"), demoTcp));
                    if (r.ok) ok++;
                    else last = r.message;
                }
                return new DemoClient.Result(ok > 0, "Mo duoc " + ok + "/" + n + " phien tu " + src
                        + (last.isEmpty() ? "" : ". Loi gan nhat: " + last));
            }
            case "send":
                return demo.send(intOf(p.get("id"), -1), p.getOrDefault("msg", "whoami"));
            case "half":
                return demo.half(intOf(p.get("id"), -1));
            case "close":
                return demo.close(intOf(p.get("id"), -1));
            case "closeall":
                return demo.closeAll();
            case "udp":
                return demo.udp(src, dst, intOf(p.get("port"), demoUdp), p.getOrDefault("msg", "xin chao"));
            case "scan":
                return demo.scan(ctx.publicIp, gw.monitorPorts());
            case "forward": {
                List<PortForwarder> f = gw.forwarders();
                if (f.isEmpty()) return new DemoClient.Result(false, "Chua cau hinh Port Forwarding.");
                return demo.forward(ctx.publicIp, f.get(0).publicPort(), p.getOrDefault("msg", "GET /trang-noi-bo"));
            }
            case "mode":
                ctx.nat.setMode(NatMode.parse(p.get("value")));
                return new DemoClient.Result(true, "Kieu NAT cho UDP: " + ctx.nat.mode().label
                        + ". Ap dung cho anh xa moi.");
            case "reload":
                ctx.firewall.load();
                return new DemoClient.Result(true, "Da nap lai " + ctx.firewall.rules().size() + " luat.");
            case "add_rule": {
                String rule = p.getOrDefault("rule", "").trim();
                if (rule.isEmpty()) return new DemoClient.Result(false, "Noi dung luat trong.");
                boolean ok = ctx.firewall.addRule(rule);
                return new DemoClient.Result(ok, ok ? "Da them luat: " + rule : "Loi cu phap luat: " + rule);
            }
            case "delete_rule": {
                int line = intOf(p.get("line"), -1);
                if (line <= 0) return new DemoClient.Result(false, "So dong khong hop le.");
                boolean ok = ctx.firewall.removeRule(line);
                return new DemoClient.Result(ok, ok ? "Da xoa luat #" + line : "Khong tim thay luat #" + line);
            }
            case "set_qos": {
                String ip = p.getOrDefault("ip", "").trim();
                int kb = intOf(p.get("limit"), 0);
                if (ip.isEmpty()) return new DemoClient.Result(false, "IP khong hop le");
                ctx.setQosLimit(ip, kb);
                return new DemoClient.Result(true, kb > 0 ? "Da gioi han " + ip + " o muc " + kb + " KB/s" : "Da huy gioi han QoS cho " + ip);
            }
            case "ban_ip": {
                String ip = p.getOrDefault("ip", "").trim();
                int sec = Math.max(5, intOf(p.get("sec"), 60));
                if (ip.isEmpty()) return new DemoClient.Result(false, "IP khong hop le");
                ctx.firewall.ban(ip, sec * 1000L, "Khoa thu cong tu Web");
                return new DemoClient.Result(true, "Da AUTO-BAN IP " + ip + " trong " + sec + " giay");
            }
            case "unban_ip": {
                String ip = p.getOrDefault("ip", "").trim();
                boolean ok = ctx.firewall.unban(ip);
                return new DemoClient.Result(ok, ok ? "Da UNBAN cho IP: " + ip : "IP khong nam trong danh sach khoa");
            }
            case "verbose":
                Log.setVerbose(!Log.isVerbose());
                return new DemoClient.Result(true, "Log chi tiet: " + (Log.isVerbose() ? "bat" : "tat"));
            default:
                return new DemoClient.Result(false, "Thao tac khong hop le: " + type);
        }
    }

    // ------------------------------------------------------------------ tiện ích
    private static int intOf(String s, int def) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
    }

    private static String readBody(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1 && bos.size() < 65536) bos.write(buf, 0, n);
        return bos.toString(StandardCharsets.UTF_8.name());
    }

    private static Map<String, String> params(String raw) {
        Map<String, String> m = new HashMap<>();
        if (raw == null || raw.isEmpty()) return m;
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) continue;
            m.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return m;
    }

    private static void send(HttpExchange ex, int code, String type, byte[] body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    private static String strArray(List<String> list) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) b.append(',');
            b.append(q(list.get(i)));
        }
        return b.append(']').toString();
    }

    /** Escape chuỗi theo chuẩn JSON. */
    static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }
}
