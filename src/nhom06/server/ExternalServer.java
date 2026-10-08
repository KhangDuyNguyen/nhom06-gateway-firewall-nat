package nhom06.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
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
 * Day chinh la bang chung truc quan cho co che NAT/PAT.
 *
 * Chay:  java -cp out nhom06.server.ExternalServer [ip] [tcpPort] [udpPort]
 */
public class ExternalServer {

    private static final SimpleDateFormat TS = new SimpleDateFormat("HH:mm:ss");
    private static final AtomicInteger connCount = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        String ip = (args.length > 0) ? args[0] : "127.0.0.3";
        int tcpPort = (args.length > 1) ? Integer.parseInt(args[1]) : 9000;
        int udpPort = (args.length > 2) ? Integer.parseInt(args[2]) : 9001;

        System.out.println("""
                ==============================================================
                   EXTERNAL SERVER (mo phong may chu Internet) - NHOM 06
                ==============================================================""");
        System.out.printf("  TCP: %s:%d    UDP: %s:%d%n", ip, tcpPort, ip, udpPort);
        System.out.println("  Server se bao lai dia chi nguon ma no nhin thay.");
        System.out.println("--------------------------------------------------------------");

        ExecutorService pool = Executors.newCachedThreadPool();
        startUdp(ip, udpPort);

        ServerSocket server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(ip, tcpPort), 100);

        while (true) {
            Socket s = server.accept();
            pool.execute(() -> handleTcp(s));
        }
    }

    private static void handleTcp(Socket s) {
        String src = s.getInetAddress().getHostAddress() + ":" + s.getPort();
        int id = connCount.incrementAndGet();
        log("[TCP #" + id + "] Ket noi moi tu " + src + "  <-- day la dia chi SAU NAT");

        try (Socket sock = s;
             BufferedReader in = new BufferedReader(
                     new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
             PrintWriter out = new PrintWriter(
                     new java.io.OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8), true)) {

            out.println("[EXT-SERVER] Xin chao! Toi nhin thay ban tai " + src);

            String line;
            while ((line = in.readLine()) != null) {
                log("[TCP #" + id + "] " + src + " gui: " + line);
                String reply;
                String cmd = line.trim().toLowerCase();
                if (cmd.equals("whoami")) {
                    reply = "[EXT-SERVER] Dia chi nguon cua ban: " + src;
                } else if (cmd.equals("time")) {
                    reply = "[EXT-SERVER] Gio server: " + new Date();
                } else if (cmd.equals("bye")) {
                    out.println("[EXT-SERVER] Tam biet " + src);
                    break;
                } else {
                    reply = "[EXT-SERVER] ECHO tu " + src + " luc " + TS.format(new Date()) + ": " + line;
                }
                out.println(reply);
            }
        } catch (IOException e) {
            // client dong ket noi
        } finally {
            log("[TCP #" + id + "] Dong ket noi " + src);
        }
    }

    private static void startUdp(String ip, int port) {
        Thread t = new Thread(() -> {
            try (DatagramSocket sock = new DatagramSocket(new InetSocketAddress(ip, port))) {
                byte[] buf = new byte[8192];
                while (true) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    sock.receive(p);
                    String src = p.getAddress().getHostAddress() + ":" + p.getPort();
                    String msg = new String(p.getData(), p.getOffset(), p.getLength(), StandardCharsets.UTF_8);
                    log("[UDP] Goi tu " + src + " : " + msg.trim());

                    String reply = "[EXT-SERVER/UDP] ECHO tu " + src + ": " + msg.trim();
                    byte[] data = reply.getBytes(StandardCharsets.UTF_8);
                    sock.send(new DatagramPacket(data, data.length, p.getAddress(), p.getPort()));
                }
            } catch (Exception e) {
                System.out.println("[UDP] Loi: " + e.getMessage());
            }
        }, "ext-udp");
        t.setDaemon(true);
        t.start();
    }

    private static void log(String msg) {
        System.out.println(TS.format(new Date()) + " " + msg);
    }
}
