package nhom06.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * EXTERNAL SERVER - mo phong may chu tren Internet.
 *
 * Diem quan trong trong de tai: server nay LUON bao lai dia chi nguon ma no
 * NHIN THAY. Vi moi luu luong deu di qua Gateway NAT nen dia chi do luon la
 * (IP cong cong, cong cong khai) chu khong phai IP rieng cua Client.
 *
 * Cac cong:
 *   TCP  ip:tcpPort        echo, whoami, time, bye; gui "dong cuoi" sau khi nhan FIN (half-close)
 *   UDP  ip:udpPort        echo; neu noi dung bat dau bang "peer" thi nho 2 may "ben thu ba"
 *                          gui them goi tin toi cung dia chi -> dung de thu cac kieu NAT
 *   UDP  ip:udpPort+1      echo (dich thu hai, de thu hanh vi anh xa cua tung kieu NAT)
 *   UDP  peerIp:udpPort+1  "ben thu ba" khac IP (mac dinh 127.0.0.4)
 *
 * Chay:  java -cp out nhom06.server.ExternalServer [ip] [tcpPort] [udpPort] [peerIp]
 */
public class ExternalServer {

    private static final SimpleDateFormat TS = new SimpleDateFormat("HH:mm:ss");
    private static final AtomicInteger connCount = new AtomicInteger();
    private static volatile boolean quiet = false;

    public static void main(String[] args) throws Exception {
        String ip = (args.length > 0) ? args[0] : "127.0.0.3";
        int tcpPort = (args.length > 1) ? Integer.parseInt(args[1]) : 9000;
        int udpPort = (args.length > 2) ? Integer.parseInt(args[2]) : 9001;
        String peerIp = (args.length > 3) ? args[3] : "127.0.0.4";

        System.out.println("""
                ==============================================================
                   EXTERNAL SERVER (mo phong may chu Internet) - NHOM 06
                ==============================================================""");
        System.out.printf("  TCP: %s:%d    UDP: %s:%d va %s:%d%n", ip, tcpPort, ip, udpPort, ip, udpPort + 1);
        System.out.println("  Server se bao lai dia chi nguon ma no nhin thay.");
        System.out.println("--------------------------------------------------------------");

        start(ip, tcpPort, udpPort, peerIp, false);
        Thread.currentThread().join();   // giu chuong trinh chay
    }

    /** Khởi động mọi dịch vụ ở luồng nền (dùng chung cho main và bộ kiểm thử). */
    public static void start(String ip, int tcpPort, int udpPort, String peerIp, boolean quietMode)
            throws IOException {
        quiet = quietMode;
        ExecutorService pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });

        // --- UDP ---
        DatagramSocket main = new DatagramSocket(new InetSocketAddress(ip, udpPort));
        DatagramSocket second = new DatagramSocket(new InetSocketAddress(ip, udpPort + 1));
        DatagramSocket otherIp = null;
        try {
            otherIp = new DatagramSocket(new InetSocketAddress(peerIp, udpPort + 1));
        } catch (IOException e) {
            log("[UDP] Khong mo duoc may 'ben thu ba' " + peerIp + ":" + (udpPort + 1)
                    + " (" + e.getMessage() + ") -> bo qua thu nghiem khac IP.");
        }
        final DatagramSocket other = otherIp;
        startUdpEcho(main, second, other, ip, udpPort, peerIp);
        startUdpEcho(second, null, null, ip, udpPort + 1, peerIp);

        // --- TCP ---
        ServerSocket server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(ip, tcpPort), 200);
        Thread acceptor = new Thread(() -> {
            while (true) {
                try {
                    Socket s = server.accept();
                    pool.execute(() -> handleTcp(s));
                } catch (IOException e) {
                    return;
                }
            }
        }, "ext-tcp-accept");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    private static void handleTcp(Socket s) {
        String src = s.getInetAddress().getHostAddress() + ":" + s.getPort();
        int id = connCount.incrementAndGet();
        log("[TCP #" + id + "] Ket noi moi tu " + src + "  <-- day la dia chi SAU NAT");

        try (Socket sock = s;
             BufferedReader in = new BufferedReader(
                     new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
             PrintWriter out = new PrintWriter(
                     new OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8), true)) {

            out.println("[EXT-SERVER] Xin chao! Toi nhin thay ban tai " + src);

            String line;
            boolean byeSent = false;
            while ((line = in.readLine()) != null) {
                log("[TCP #" + id + "] " + src + " gui: " + line);
                String cmd = line.trim().toLowerCase();
                if (cmd.equals("whoami")) {
                    out.println("[EXT-SERVER] Dia chi nguon cua ban: " + src);
                } else if (cmd.equals("time")) {
                    out.println("[EXT-SERVER] Gio server: " + new Date());
                } else if (cmd.equals("bye")) {
                    out.println("[EXT-SERVER] Tam biet " + src);
                    byeSent = true;
                    break;
                } else {
                    out.println("[EXT-SERVER] ECHO tu " + src + " luc " + TS.format(new Date()) + ": " + line);
                }
            }
            if (!byeSent) {
                // Client da gui FIN (half-close): chieu server -> client VAN con mo
                log("[TCP #" + id + "] Nhan FIN tu " + src + " -> gui dong cuoi roi dong");
                out.println("[EXT-SERVER] Da nhan FIN tu " + src
                        + ". Dong nay gui SAU khi ban dong chieu gui (half-close).");
            }
        } catch (IOException e) {
            // client ngat ket noi dot ngot
        } finally {
            log("[TCP #" + id + "] Dong ket noi " + src);
        }
    }

    private static void startUdpEcho(DatagramSocket sock, DatagramSocket peerSameIp, DatagramSocket peerOtherIp,
                                     String ip, int port, String peerIp) {
        Thread t = new Thread(() -> {
            byte[] buf = new byte[8192];
            while (!sock.isClosed()) {
                try {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    sock.receive(p);
                    String src = p.getAddress().getHostAddress() + ":" + p.getPort();
                    String msg = new String(p.getData(), p.getOffset(), p.getLength(), StandardCharsets.UTF_8).trim();
                    log("[UDP " + port + "] Goi tu " + src + " : " + msg);

                    reply(sock, p, "[EXT-SERVER/UDP " + ip + ":" + port + "] ECHO tu " + src + ": " + msg);

                    if (msg.toLowerCase().startsWith("peer") && peerSameIp != null) {
                        // Hai may "ben thu ba" chu dong gui toi dia chi cong khai vua thay
                        reply(peerSameIp, p, "[BEN THU BA " + ip + ":" + (port + 1)
                                + "] goi chu dong tu may cung IP, khac cong");
                        if (peerOtherIp != null) {
                            reply(peerOtherIp, p, "[BEN THU BA " + peerIp + ":" + (port + 1)
                                    + "] goi chu dong tu may khac IP");
                        }
                        log("[UDP] Ben thu ba da gui goi chu dong toi " + src);
                    }
                } catch (Exception e) {
                    if (!sock.isClosed()) log("[UDP] Loi: " + e.getMessage());
                }
            }
        }, "ext-udp-" + port);
        t.setDaemon(true);
        t.start();
    }

    private static void reply(DatagramSocket via, DatagramPacket to, String text) throws IOException {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        via.send(new DatagramPacket(data, data.length, to.getAddress(), to.getPort()));
    }

    private static void log(String msg) {
        if (!quiet) System.out.println(TS.format(new Date()) + " " + msg);
    }
}
