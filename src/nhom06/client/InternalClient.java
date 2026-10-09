package nhom06.client;

import nhom06.common.Config;
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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * CLIENT NOI BO - mo phong mot may tram trong mang LAN.
 *
 * Client chi biet duy nhat dia chi Gateway (default gateway). Moi ket noi ra
 * ngoai deu phai di qua Gateway; dia chi IP rieng cua no khong bao gio xuat hien
 * o phia External Server.
 *
 * Chay:  java -cp out nhom06.client.InternalClient [ipNoiBo] [configPath]
 * Vi du: java -cp out nhom06.client.InternalClient 127.0.0.11
 */
public class InternalClient {

    private static final AtomicInteger SESSION_ID = new AtomicInteger();
    private final Map<Integer, Session> sessions = new ConcurrentHashMap<>();

    private final String myIp;
    private final String gwIp;
    private final int gwTcpPort;
    private final int gwUdpPort;
    private DatagramSocket udpSocket;

    public InternalClient(String myIp, Config cfg) {
        this.myIp = myIp;
        this.gwIp = cfg.get("gateway.lan.ip", "127.0.0.1");
        this.gwTcpPort = cfg.getInt("gateway.lan.tcp.port", 8080);
        this.gwUdpPort = cfg.getInt("gateway.lan.udp.port", 8081);
    }

    public static void main(String[] args) throws Exception {
        String ip = (args.length > 0) ? args[0] : "127.0.0.11";
        String cfgPath = (args.length > 1) ? args[1] : "config/gateway.properties";
        new InternalClient(ip, new Config(cfgPath)).run();
    }

    private void run() throws IOException {
        System.out.println("""
                ==============================================================
                   CLIENT NOI BO (mo phong may trong LAN) - NHOM 06
                ==============================================================""");
        System.out.printf("  IP noi bo cua toi : %s%n", myIp);
        System.out.printf("  Default gateway   : %s (TCP %d / UDP %d)%n", gwIp, gwTcpPort, gwUdpPort);
        help();

        startUdpReceiver();

        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = stdin.readLine()) != null) {
            String[] t = line.trim().split("\\s+", 4);
            if (t[0].isEmpty()) continue;
            try {
                switch (t[0].toLowerCase()) {
                    case "open":
                        open(t[1], Integer.parseInt(t[2]));
                        break;
                    case "multi":
                        int n = Integer.parseInt(t[1]);
                        for (int i = 0; i < n; i++) open(t[2], Integer.parseInt(t[3]));
                        break;
                    case "send":
                        send(Integer.parseInt(t[1]), t.length > 2 ? joinRest(t, 2) : "");
                        break;
                    case "udp":
                        udpSend(t[1], Integer.parseInt(t[2]), t.length > 3 ? t[3] : "hello");
                        break;
                    case "list":
                        list();
                        break;
                    case "close":
                        close(Integer.parseInt(t[1]));
                        break;
                    case "half":
                        half(Integer.parseInt(t[1]));
                        break;
                    case "help":
                        help();
                        break;
                    case "quit":
                    case "exit":
                        sessions.values().forEach(Session::close);
                        if (udpSocket != null) udpSocket.close();
                        return;
                    default:
                        System.out.println("Lenh khong hop le. Go 'help'.");
                }
            } catch (Exception e) {
                System.out.println("[LOI] " + e.getMessage());
            }
        }
    }

    private static String joinRest(String[] t, int from) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < t.length; i++) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(t[i]);
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    //  TCP qua Gateway
    // ------------------------------------------------------------------
    private void open(String destIp, int destPort) {
        try {
            Socket s = new Socket();
            s.setReuseAddress(true);
            try {
                s.bind(new InetSocketAddress(myIp, 0));   // gan IP rieng cua may trong LAN
            } catch (IOException bindErr) {
                System.out.println("[CANH BAO] Khong bind duoc " + myIp + " -> dung IP mac dinh.");
            }
            s.connect(new InetSocketAddress(gwIp, gwTcpPort), 5000);

            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();

            // Khai bao dia chi dich cho Gateway
            out.write(Tunnel.connectRequest(destIp, destPort).getBytes(StandardCharsets.UTF_8));
            out.flush();

            String reply = Tunnel.readLine(in);
            if (reply == null) {
                System.out.println("[LOI] Gateway dong ket noi.");
                s.close();
                return;
            }
            String[] t = Tunnel.tokens(reply);
            if (t.length < 3 || !t[1].equals("200")) {
                System.out.println("[GATEWAY TU CHOI] " + reply);
                s.close();
                return;
            }

            int id = SESSION_ID.incrementAndGet();
            Session ses = new Session(id, s, in, out, destIp, destPort,
                    t.length > 3 ? t[3] : "?", t.length > 4 ? t[4] : "?");
            sessions.put(id, ses);
            ses.startReader();

            System.out.printf("[PHIEN #%d] %s:%d --NAT--> %s:%s --> %s:%d%n",
                    id, myIp, s.getLocalPort(), ses.publicIp, ses.publicPort, destIp, destPort);
        } catch (IOException e) {
            System.out.println("[LOI] Khong ket noi duoc Gateway: " + e.getMessage());
        }
    }

    private void send(int id, String msg) throws IOException {
        Session s = sessions.get(id);
        if (s == null) {
            System.out.println("[LOI] Khong co phien #" + id);
            return;
        }
        s.out.write((msg + "\n").getBytes(StandardCharsets.UTF_8));
        s.out.flush();
    }

    /** Dong MOT chieu (gui FIN) nhung van nhan du lieu - minh hoa TCP half-close. */
    private void half(int id) throws IOException {
        Session s = sessions.get(id);
        if (s == null) {
            System.out.println("[LOI] Khong co phien #" + id);
            return;
        }
        s.socket.shutdownOutput();
        System.out.println("[PHIEN #" + id + "] Da gui FIN (half-close): khong gui duoc nua nhung van nhan du lieu.");
    }

    private void close(int id) {
        Session s = sessions.remove(id);
        if (s != null) {
            s.close();
            System.out.println("[PHIEN #" + id + "] da dong.");
        }
    }

    private void list() {
        System.out.println("\n--- CAC PHIEN DANG MO ---");
        if (sessions.isEmpty()) System.out.println("  (khong co)");
        sessions.values().stream()
                .sorted((a, b) -> Integer.compare(a.id, b.id))
                .forEach(s -> System.out.printf("  #%d  %s:%d -> [NAT %s:%s] -> %s:%d%n",
                        s.id, myIp, s.socket.getLocalPort(), s.publicIp, s.publicPort,
                        s.destIp, s.destPort));
        System.out.println();
    }

    // ------------------------------------------------------------------
    //  UDP qua Gateway
    // ------------------------------------------------------------------
    private void startUdpReceiver() {
        try {
            udpSocket = new DatagramSocket(null);
            udpSocket.setReuseAddress(true);
            try {
                udpSocket.bind(new InetSocketAddress(myIp, 0));
            } catch (IOException e) {
                udpSocket.bind(new InetSocketAddress(0));
            }
            Thread t = new Thread(() -> {
                byte[] buf = new byte[8192];
                while (!udpSocket.isClosed()) {
                    try {
                        DatagramPacket p = new DatagramPacket(buf, buf.length);
                        udpSocket.receive(p);
                        String s = new String(p.getData(), p.getOffset(), p.getLength(),
                                StandardCharsets.UTF_8);
                        int nl = s.indexOf('\n');
                        String head = (nl > 0) ? s.substring(0, nl) : "";
                        String body = (nl > 0) ? s.substring(nl + 1) : s;
                        System.out.println("  <UDP " + head.replace(Tunnel.VERSION + " FROM ", "tu ")
                                + "> " + body.trim());
                    } catch (IOException e) {
                        return;
                    }
                }
            }, "client-udp-recv");
            t.setDaemon(true);
            t.start();
        } catch (Exception e) {
            System.out.println("[LOI] Khong mo duoc socket UDP: " + e.getMessage());
        }
    }

    private void udpSend(String destIp, int destPort, String msg) throws IOException {
        byte[] head = Tunnel.sendHeader(destIp, destPort).getBytes(StandardCharsets.UTF_8);
        byte[] body = msg.getBytes(StandardCharsets.UTF_8);
        byte[] all = new byte[head.length + body.length];
        System.arraycopy(head, 0, all, 0, head.length);
        System.arraycopy(body, 0, all, head.length, body.length);
        udpSocket.send(new DatagramPacket(all, all.length,
                InetAddress.getByName(gwIp), gwUdpPort));
        System.out.printf("  >UDP gui %d byte toi %s:%d (qua Gateway, cong nguon cuc bo %d)%n",
                body.length, destIp, destPort, udpSocket.getLocalPort());
    }

    private void help() {
        System.out.println("""

                --- LENH CLIENT ---
                  open <ipDich> <congDich>          Mo mot phien TCP ra ngoai qua Gateway
                  multi <n> <ipDich> <congDich>     Mo n phien cung luc (minh hoa PAT nhieu cong)
                  send <idPhien> <noi dung>         Gui du lieu tren phien da mo
                  udp <ipDich> <congDich> <noiDung> Gui mot goi UDP ra ngoai
                  list                              Liet ke cac phien dang mo
                  half <idPhien>                    Dong mot chieu (gui FIN), van nhan du lieu
                  close <idPhien>                   Dong mot phien
                  quit                              Thoat
                """);
    }

    /** Mot phien TCP di qua Gateway. */
    private class Session {
        final int id;
        final Socket socket;
        final InputStream in;
        final OutputStream out;
        final String destIp;
        final int destPort;
        final String publicIp;
        final String publicPort;

        Session(int id, Socket socket, InputStream in, OutputStream out,
                String destIp, int destPort, String publicIp, String publicPort) {
            this.id = id;
            this.socket = socket;
            this.in = in;
            this.out = out;
            this.destIp = destIp;
            this.destPort = destPort;
            this.publicIp = publicIp;
            this.publicPort = publicPort;
        }

        void startReader() {
            Thread t = new Thread(() -> {
                try {
                    BufferedReader br = new BufferedReader(
                            new InputStreamReader(in, StandardCharsets.UTF_8));
                    String line;
                    while ((line = br.readLine()) != null) {
                        System.out.println("  <#" + id + "> " + line);
                    }
                } catch (IOException ignored) {
                } finally {
                    sessions.remove(id);
                    System.out.println("  [#" + id + "] phien da ket thuc.");
                }
            }, "session-" + id);
            t.setDaemon(true);
            t.start();
        }

        void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }
}
