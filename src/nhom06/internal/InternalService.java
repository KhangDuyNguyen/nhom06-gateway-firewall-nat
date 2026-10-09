package nhom06.internal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * INTERNAL SERVICE - mot dich vu nam BEN TRONG mang LAN (vi du web server noi bo).
 *
 * Dung de minh hoa chuc nang Port Forwarding (NAT tinh): may chu ben ngoai
 * khong the truy cap truc tiep dich vu nay, nhung Gateway mo mot cong cong khai
 * va chuyen tiep vao day.
 *
 * Chay:  java -cp out nhom06.internal.InternalService [ip] [port]
 */
public class InternalService {

    private static final SimpleDateFormat TS = new SimpleDateFormat("HH:mm:ss");
    private static volatile boolean quiet = false;

    public static void main(String[] args) throws Exception {
        String ip = (args.length > 0) ? args[0] : "127.0.0.20";
        int port = (args.length > 1) ? Integer.parseInt(args[1]) : 7000;

        System.out.println("""
                ==============================================================
                   INTERNAL SERVICE (dich vu trong LAN) - NHOM 06
                ==============================================================""");
        System.out.printf("  Lang nghe tai %s:%d (chi truy cap duoc qua Port Forwarding)%n", ip, port);
        System.out.println("--------------------------------------------------------------");

        start(ip, port, false);
        Thread.currentThread().join();
    }

    /** Khởi động dịch vụ ở luồng nền (dùng chung cho main và bộ kiểm thử). */
    public static void start(String ip, int port, boolean quietMode) throws IOException {
        quiet = quietMode;
        ExecutorService pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });
        ServerSocket server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(ip, port), 50);
        Thread acceptor = new Thread(() -> {
            while (true) {
                try {
                    Socket s = server.accept();
                    pool.execute(() -> handle(s));
                } catch (IOException e) {
                    return;
                }
            }
        }, "internal-service-accept");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    private static void handle(Socket s) {
        String src = s.getInetAddress().getHostAddress() + ":" + s.getPort();
        log("[LAN-SERVICE] Ket noi tu " + src + " (di qua Gateway)");
        try (Socket sock = s;
             BufferedReader in = new BufferedReader(
                     new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
             PrintWriter out = new PrintWriter(
                     new OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8), true)) {

            out.println("[LAN-SERVICE] Ban da vao duoc dich vu noi bo qua Port Forwarding!");
            String line;
            while ((line = in.readLine()) != null) {
                log("[LAN-SERVICE] nhan: " + line);
                if (line.trim().equalsIgnoreCase("bye")) {
                    out.println("[LAN-SERVICE] Tam biet.");
                    break;
                }
                out.println("[LAN-SERVICE] Da xu ly yeu cau: " + line);
            }
        } catch (IOException ignored) {
        }
    }

    private static void log(String msg) {
        if (!quiet) System.out.println(TS.format(new Date()) + " " + msg);
    }
}
