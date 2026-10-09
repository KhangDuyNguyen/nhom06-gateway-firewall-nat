package nhom06.test;

import nhom06.common.Config;
import nhom06.common.Log;
import nhom06.common.Tunnel;
import nhom06.gateway.GatewayServer;
import nhom06.internal.InternalService;
import nhom06.server.ExternalServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Môi trường kiểm thử: dựng External Server, Internal Service và Gateway NGAY TRONG
 * một tiến trình (cổng riêng, không đụng bản demo), kèm các hàm tiện ích để đóng vai Client.
 */
public class TestEnv {

    public final GatewayServer gw;
    public final String lanIp;
    public final int lanTcp;
    public final int lanUdp;
    public final String publicIp;
    public final boolean peerOtherIpAvailable;

    private TestEnv(GatewayServer gw, boolean peerOther) {
        this.gw = gw;
        this.lanIp = gw.context().lanIp;
        this.lanTcp = gw.lanTcpPort();
        this.lanUdp = gw.lanUdpPort();
        this.publicIp = gw.context().publicIp;
        this.peerOtherIpAvailable = peerOther;
    }

    private TestEnv(Config cfg) {
        this.gw = null;
        this.lanIp = cfg.get("gateway.lan.ip", "127.0.0.1");
        this.lanTcp = cfg.getInt("gateway.lan.tcp.port", 8080);
        this.lanUdp = cfg.getInt("gateway.lan.udp.port", 8081);
        this.publicIp = cfg.get("gateway.public.ip", "127.0.0.2");
        this.peerOtherIpAvailable = false;
    }

    /** Gắn vào Gateway demo ĐANG CHẠY (không tự dựng môi trường). */
    public static TestEnv attach(Config cfg) {
        return new TestEnv(cfg);
    }

    public static TestEnv start(String name, Properties p, String rules,
                                String extIp, int extTcp, int extUdp, String peerIp,
                                String intIp, int intPort) throws Exception {
        Files.createDirectories(Paths.get("logs"));
        Path rulesPath = Paths.get("logs", name + "-rules.txt");
        Files.write(rulesPath, rules.getBytes(StandardCharsets.UTF_8));
        p.setProperty("firewall.rules.file", rulesPath.toString());
        p.setProperty("web.enabled", "false");
        Log.init(p.getProperty("log.file", "logs/" + name + ".log"), false);
        Log.setConsole(false);

        boolean peerOther = canBindUdp(peerIp);
        ExternalServer.start(extIp, extTcp, extUdp, peerIp, true);
        if (intIp != null) InternalService.start(intIp, intPort, true);
        GatewayServer gw = new GatewayServer(new Config(p));
        gw.startServices(false);
        return new TestEnv(gw, peerOther);
    }

    private static boolean canBindUdp(String ip) {
        try (DatagramSocket s = new DatagramSocket(new InetSocketAddress(ip, 0))) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // ------------------------------------------------------------------ TCP
    public Conn open(String srcIp, String destIp, int destPort) throws IOException {
        Socket s = new Socket();
        s.setReuseAddress(true);
        try {
            s.bind(new InetSocketAddress(srcIp, 0));
        } catch (IOException e) {
            s.bind(new InetSocketAddress(lanIp, 0));   // HĐH không cho dùng IP này -> dùng IP mặc định
        }
        s.connect(new InetSocketAddress(lanIp, lanTcp), 3000);
        s.setSoTimeout(4000);
        OutputStream out = s.getOutputStream();
        out.write(Tunnel.connectRequest(destIp, destPort).getBytes(StandardCharsets.UTF_8));
        out.flush();
        InputStream in = s.getInputStream();
        String reply = Tunnel.readLine(in);
        return new Conn(s, in, out, reply == null ? "" : reply);
    }

    /** Một phiên TCP đi qua Gateway. */
    public static class Conn {
        public final Socket socket;
        public final String reply;
        public final boolean ok;
        public final String publicAddr;
        private final BufferedReader reader;
        private final OutputStream out;

        Conn(Socket socket, InputStream in, OutputStream out, String reply) {
            this.socket = socket;
            this.reply = reply;
            String[] t = Tunnel.tokens(reply);
            this.ok = t.length >= 5 && "200".equals(t[1]);
            this.publicAddr = ok ? t[3] + ":" + t[4] : null;
            this.reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            this.out = out;
        }

        public String readLine() throws IOException {
            return reader.readLine();
        }

        public void send(String msg) throws IOException {
            out.write((msg + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
        }

        /** Kết thúc lịch sự: server đóng trước (tránh TIME_WAIT ở phía Gateway). */
        public void bye() {
            try {
                if (ok) {
                    send("bye");
                    while (readLine() != null) { /* đọc tới khi server đóng */ }
                }
            } catch (IOException ignored) {
            } finally {
                close();
            }
        }

        public void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    // ------------------------------------------------------------------ UDP
    public Udp udp(String srcIp) throws IOException {
        DatagramSocket ds = new DatagramSocket(null);
        ds.setReuseAddress(true);
        try {
            ds.bind(new InetSocketAddress(srcIp, 0));
        } catch (IOException e) {
            ds.bind(new InetSocketAddress(lanIp, 0));
        }
        return new Udp(ds, lanIp, lanUdp);
    }

    /** Một gói UDP nhận về: nguồn (theo header FROM của Gateway) và nội dung. */
    public static class Msg {
        public final String from;
        public final String body;

        Msg(String from, String body) {
            this.from = from;
            this.body = body;
        }

        @Override
        public String toString() {
            return from + " | " + body;
        }
    }

    public static class Udp {
        public final DatagramSocket socket;
        private final String gwIp;
        private final int gwPort;

        Udp(DatagramSocket socket, String gwIp, int gwPort) {
            this.socket = socket;
            this.gwIp = gwIp;
            this.gwPort = gwPort;
        }

        public void send(String destIp, int destPort, String msg) throws IOException {
            byte[] head = Tunnel.sendHeader(destIp, destPort).getBytes(StandardCharsets.UTF_8);
            byte[] body = msg.getBytes(StandardCharsets.UTF_8);
            byte[] all = new byte[head.length + body.length];
            System.arraycopy(head, 0, all, 0, head.length);
            System.arraycopy(body, 0, all, head.length, body.length);
            socket.send(new DatagramPacket(all, all.length, InetAddress.getByName(gwIp), gwPort));
        }

        /** Nhận mọi gói tới trong khoảng thời gian cho trước. */
        public List<Msg> receive(long windowMs) throws IOException {
            List<Msg> out = new ArrayList<>();
            long end = System.currentTimeMillis() + windowMs;
            byte[] buf = new byte[8192];
            while (true) {
                long left = end - System.currentTimeMillis();
                if (left <= 0) break;
                socket.setSoTimeout((int) Math.max(1, left));
                try {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    socket.receive(p);
                    String s = new String(p.getData(), p.getOffset(), p.getLength(), StandardCharsets.UTF_8);
                    int nl = s.indexOf('\n');
                    String from = "?";
                    String body = s;
                    if (nl > 0) {
                        String[] h = Tunnel.tokens(s.substring(0, nl));
                        if (h.length >= 4) from = h[2] + ":" + h[3];
                        body = s.substring(nl + 1);
                    }
                    out.add(new Msg(from, body.trim()));
                } catch (SocketTimeoutException e) {
                    break;
                }
            }
            return out;
        }

        public void close() {
            socket.close();
        }
    }

    private static final java.util.regex.Pattern ADDR =
            java.util.regex.Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+");

    /** Lấy "IP:cổng" mà server nhìn thấy từ câu ECHO / chào của External Server. */
    public static String seenAddress(String line) {
        if (line == null) return null;
        int i = line.indexOf("ECHO tu ");
        java.util.regex.Matcher m = ADDR.matcher(i >= 0 ? line.substring(i) : line);
        return m.find() ? m.group() : null;
    }
}
