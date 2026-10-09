package nhom06.gateway;

import nhom06.common.Tunnel;

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
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Client demo dùng cho Web dashboard: khi người dùng bấm nút trên trang web, lớp này
 * đóng vai MỘT MÁY TRONG LAN (bind đúng IP nội bộ được chọn) và đi qua Gateway y hệt
 * InternalClient. Nhờ vậy mọi thao tác trên web đều đi qua đúng đường NAT/Firewall thật.
 */
public class DemoClient {

    private static final SimpleDateFormat TS = new SimpleDateFormat("HH:mm:ss");

    /** Kết quả một thao tác, trả về cho trang web. */
    public static class Result {
        public final boolean ok;
        public final String message;

        Result(boolean ok, String message) {
            this.ok = ok;
            this.message = message;
        }
    }

    /** Một phiên TCP do web mở. */
    public static class Session {
        public final int id;
        public final String srcIp;
        public final int localPort;
        public final String destIp;
        public final int destPort;
        public final String publicAddr;
        volatile String status = "OPEN";      // OPEN | HALF | CLOSED
        volatile long closedAt = 0;
        private final Deque<String> lines = new ArrayDeque<>();
        final Socket socket;
        final OutputStream out;

        Session(int id, String srcIp, int localPort, String destIp, int destPort,
                String publicAddr, Socket socket, OutputStream out) {
            this.id = id;
            this.srcIp = srcIp;
            this.localPort = localPort;
            this.destIp = destIp;
            this.destPort = destPort;
            this.publicAddr = publicAddr;
            this.socket = socket;
            this.out = out;
        }

        synchronized void addLine(String l) {
            if (lines.size() >= 40) lines.removeFirst();
            lines.addLast(TS.format(new Date()) + "  " + l);
        }

        public synchronized List<String> lines() {
            return new ArrayList<>(lines);
        }

        public String status() {
            return status;
        }
    }

    /** Một sự kiện UDP (gửi đi hoặc nhận về). */
    public static class UdpEvent {
        public final String time;
        public final String host;
        public final String peer;
        public final boolean outgoing;
        public final String text;

        UdpEvent(String host, String peer, boolean outgoing, String text) {
            this.time = TS.format(new Date());
            this.host = host;
            this.peer = peer;
            this.outgoing = outgoing;
            this.text = text;
        }
    }

    private final String gwIp;
    private final int gwTcp;
    private final int gwUdp;
    private final Map<Integer, Session> sessions = new ConcurrentHashMap<>();
    private final AtomicInteger seq = new AtomicInteger();
    private final Map<String, DatagramSocket> udpSockets = new ConcurrentHashMap<>();
    private final Deque<UdpEvent> udpEvents = new ArrayDeque<>();

    public DemoClient(String gwIp, int gwTcp, int gwUdp) {
        this.gwIp = gwIp;
        this.gwTcp = gwTcp;
        this.gwUdp = gwUdp;
    }

    // ------------------------------------------------------------------ TCP
    public Result open(String srcIp, String destIp, int destPort) {
        Socket s = new Socket();
        try {
            s.setReuseAddress(true);
            try {
                s.bind(new InetSocketAddress(srcIp, 0));
            } catch (IOException e) {
                s.close();
                return new Result(false, "Khong dung duoc dia chi " + srcIp + ": " + e.getMessage());
            }
            s.connect(new InetSocketAddress(gwIp, gwTcp), 3000);
            s.setSoTimeout(8000);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            out.write(Tunnel.connectRequest(destIp, destPort).getBytes(StandardCharsets.UTF_8));
            out.flush();

            String reply = Tunnel.readLine(in);
            if (reply == null) {
                s.close();
                return new Result(false, "Gateway dong ket noi ma khong tra loi.");
            }
            String[] t = Tunnel.tokens(reply);
            if (t.length < 5 || !"200".equals(t[1])) {
                s.close();
                return new Result(false, "Gateway tu choi: " + reply.replace(Tunnel.VERSION + " ", ""));
            }
            s.setSoTimeout(0);

            int id = seq.incrementAndGet();
            Session ses = new Session(id, srcIp, s.getLocalPort(), destIp, destPort,
                    t[3] + ":" + t[4], s, out);
            sessions.put(id, ses);
            startReader(ses, in);
            return new Result(true, "Phien #" + id + ": " + srcIp + ":" + ses.localPort + " -> "
                    + ses.publicAddr + " -> " + destIp + ":" + destPort);
        } catch (IOException e) {
            try {
                s.close();
            } catch (IOException ignored) {
            }
            return new Result(false, "Khong ket noi duoc Gateway: " + e.getMessage());
        }
    }

    private void startReader(Session ses, InputStream in) {
        Thread t = new Thread(() -> {
            try {
                BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                String line;
                while ((line = br.readLine()) != null) ses.addLine("<- " + line);
                ses.addLine("(server da dong chieu gui - nhan FIN)");
            } catch (IOException e) {
                if (!"CLOSED".equals(ses.status)) ses.addLine("(ket noi bi ngat: " + e.getMessage() + ")");
            } finally {
                ses.status = "CLOSED";
                if (ses.closedAt == 0) ses.closedAt = System.currentTimeMillis();
                try {
                    ses.socket.close();
                } catch (IOException ignored) {
                }
            }
        }, "demo-session-" + ses.id);
        t.setDaemon(true);
        t.start();
    }

    public Result send(int id, String msg) {
        Session s = sessions.get(id);
        if (s == null || "CLOSED".equals(s.status)) return new Result(false, "Phien #" + id + " khong con mo.");
        if ("HALF".equals(s.status)) return new Result(false, "Phien #" + id + " da gui FIN, khong gui them duoc.");
        try {
            s.out.write((msg + "\n").getBytes(StandardCharsets.UTF_8));
            s.out.flush();
            s.addLine("-> " + msg);
            return new Result(true, "Da gui tren phien #" + id);
        } catch (IOException e) {
            return new Result(false, "Loi gui: " + e.getMessage());
        }
    }

    /** Đóng MỘT chiều (gửi FIN) nhưng vẫn nhận dữ liệu — minh hoạ TCP half-close. */
    public Result half(int id) {
        Session s = sessions.get(id);
        if (s == null || !"OPEN".equals(s.status)) return new Result(false, "Phien #" + id + " khong o trang thai OPEN.");
        try {
            s.socket.shutdownOutput();
            s.status = "HALF";
            s.addLine("(da gui FIN: ngung gui nhung van nhan du lieu)");
            return new Result(true, "Phien #" + id + " da gui FIN (half-close).");
        } catch (IOException e) {
            return new Result(false, "Loi: " + e.getMessage());
        }
    }

    public Result close(int id) {
        Session s = sessions.get(id);
        if (s == null) return new Result(false, "Khong co phien #" + id);
        s.status = "CLOSED";
        s.closedAt = System.currentTimeMillis();
        try {
            s.socket.close();
        } catch (IOException ignored) {
        }
        return new Result(true, "Da dong phien #" + id);
    }

    public Result closeAll() {
        int n = 0;
        for (Session s : sessions.values()) {
            if (!"CLOSED".equals(s.status)) {
                close(s.id);
                n++;
            }
        }
        return new Result(true, "Da dong " + n + " phien.");
    }

    /** Danh sách phiên; phiên đã đóng được giữ lại 30 giây rồi ẩn đi. */
    public List<Session> sessions() {
        long now = System.currentTimeMillis();
        sessions.values().removeIf(s -> "CLOSED".equals(s.status) && s.closedAt > 0 && now - s.closedAt > 30000);
        List<Session> list = new ArrayList<>(sessions.values());
        list.sort(Comparator.comparingInt(s -> s.id));
        return list;
    }

    // ------------------------------------------------------------------ UDP
    public Result udp(String srcIp, String destIp, int destPort, String msg) {
        try {
            DatagramSocket ds = udpSocketFor(srcIp);
            byte[] head = Tunnel.sendHeader(destIp, destPort).getBytes(StandardCharsets.UTF_8);
            byte[] body = msg.getBytes(StandardCharsets.UTF_8);
            byte[] all = new byte[head.length + body.length];
            System.arraycopy(head, 0, all, 0, head.length);
            System.arraycopy(body, 0, all, head.length, body.length);
            ds.send(new DatagramPacket(all, all.length, InetAddress.getByName(gwIp), gwUdp));
            String host = srcIp + ":" + ds.getLocalPort();
            addUdp(new UdpEvent(host, destIp + ":" + destPort, true, msg));
            return new Result(true, "Da gui UDP tu " + host + " toi " + destIp + ":" + destPort);
        } catch (IOException e) {
            return new Result(false, "Loi UDP: " + e.getMessage());
        }
    }

    /** Mỗi IP nội bộ dùng MỘT socket UDP cố định để thấy rõ hành vi ánh xạ của từng kiểu NAT. */
    private DatagramSocket udpSocketFor(String srcIp) throws IOException {
        DatagramSocket existing = udpSockets.get(srcIp);
        if (existing != null && !existing.isClosed()) return existing;
        DatagramSocket ds = new DatagramSocket(null);
        ds.setReuseAddress(true);
        ds.bind(new InetSocketAddress(srcIp, 0));
        udpSockets.put(srcIp, ds);
        String host = srcIp + ":" + ds.getLocalPort();
        Thread t = new Thread(() -> {
            byte[] buf = new byte[8192];
            while (!ds.isClosed()) {
                try {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    ds.receive(p);
                    String s = new String(p.getData(), p.getOffset(), p.getLength(), StandardCharsets.UTF_8);
                    int nl = s.indexOf('\n');
                    String from = "?";
                    String body = s;
                    if (nl > 0) {
                        String[] h = Tunnel.tokens(s.substring(0, nl));
                        if (h.length >= 4) from = h[2] + ":" + h[3];
                        body = s.substring(nl + 1);
                    }
                    addUdp(new UdpEvent(host, from, false, body.trim()));
                } catch (IOException e) {
                    return;
                }
            }
        }, "demo-udp-" + srcIp);
        t.setDaemon(true);
        t.start();
        return ds;
    }

    private synchronized void addUdp(UdpEvent e) {
        if (udpEvents.size() >= 30) udpEvents.removeFirst();
        udpEvents.addLast(e);
    }

    public synchronized List<UdpEvent> udpEvents() {
        return new ArrayList<>(udpEvents);
    }

    // ------------------------------------------------------------------ từ bên ngoài
    /** Mô phỏng một máy bên ngoài lần lượt thử kết nối vào nhiều cổng (quét cổng). */
    public Result scan(String publicIp, List<Integer> ports) {
        if (ports.isEmpty()) return new Result(false, "Khong co cong giam sat nao duoc cau hinh.");
        CountDownLatch done = new CountDownLatch(ports.size());
        for (int p : ports) {
            Thread t = new Thread(() -> {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(publicIp, p), 1500);
                } catch (IOException ignored) {
                } finally {
                    done.countDown();
                }
            });
            t.setDaemon(true);
            t.start();
        }
        try {
            done.await();
        } catch (InterruptedException ignored) {
        }
        return new Result(true, "Da tham do " + ports.size() + " cong " + ports + " tren " + publicIp
                + ". Xem canh bao an ninh.");
    }

    /** Mô phỏng máy bên ngoài truy cập dịch vụ nội bộ qua Port Forwarding. */
    public Result forward(String publicIp, int port, String msg) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(publicIp, port), 2000);
            s.setSoTimeout(3000);
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            OutputStream out = s.getOutputStream();
            String banner = in.readLine();
            if (banner == null) return new Result(false, "Ket noi vao " + publicIp + ":" + port + " bi dong ngay (bi chan?).");
            out.write((msg + "\nbye\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            String reply = in.readLine();
            return new Result(true, banner + " | " + (reply == null ? "" : reply));
        } catch (IOException e) {
            return new Result(false, "Khong vao duoc " + publicIp + ":" + port + ": " + e.getMessage());
        }
    }

    public void shutdown() {
        closeAll();
        udpSockets.values().forEach(DatagramSocket::close);
    }
}
