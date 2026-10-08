package nhom06.gateway;

import nhom06.common.Log;
import nhom06.common.Protocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * NAT TĨNH (Port Forwarding / DNAT).
 *
 * Gateway mở một cổng trên IP công cộng; mọi kết nối từ bên ngoài tới cổng đó
 * được chuyển thẳng vào một dịch vụ trong mạng LAN. Đây là chiều ngược lại của
 * NAT động: bên ngoài chủ động khởi tạo kết nối vào bên trong.
 *
 * Cấu hình:  portforward.1 = <publicPort>&gt;<internalIp>:<internalPort>
 */
public class PortForwarder implements Runnable {

    private final GatewayContext ctx;
    private final int publicPort;
    private final String internalIp;
    private final int internalPort;
    private ServerSocket server;
    private volatile boolean running = true;

    public PortForwarder(GatewayContext ctx, int publicPort, String internalIp, int internalPort) {
        this.ctx = ctx;
        this.publicPort = publicPort;
        this.internalIp = internalIp;
        this.internalPort = internalPort;
    }

    /** Phân tích chuỗi "8090>127.0.0.20:7000". */
    public static PortForwarder parse(GatewayContext ctx, String spec) {
        String[] a = spec.split(">");
        if (a.length != 2) throw new IllegalArgumentException("Sai dinh dang port-forward: " + spec);
        String[] b = a[1].split(":");
        if (b.length != 2) throw new IllegalArgumentException("Sai dinh dang dich: " + spec);
        return new PortForwarder(ctx, Integer.parseInt(a[0].trim()),
                b[0].trim(), Integer.parseInt(b[1].trim()));
    }

    public void start() throws IOException {
        server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(ctx.publicIp, publicPort));
        Log.info("PORT-FWD", String.format("NAT tinh: %s:%d  ==>  %s:%d",
                ctx.publicIp, publicPort, internalIp, internalPort));
        Thread t = new Thread(this, "port-forward-" + publicPort);
        t.setDaemon(true);
        t.start();
    }

    @Override
    public void run() {
        while (running) {
            try {
                Socket outside = server.accept();
                ctx.pool.execute(() -> handle(outside));
            } catch (IOException e) {
                if (running) Log.error("PORT-FWD", "Loi accept: " + e.getMessage());
            }
        }
    }

    private void handle(Socket outside) {
        String srcIp = outside.getInetAddress().getHostAddress();
        int srcPort = outside.getPort();
        String tag = "PF " + srcIp + ":" + srcPort;
        Socket inside = null;
        NatEntry entry = null;

        try {
            // Firewall chiều VÀO
            Firewall.Decision d = ctx.firewall.check(FirewallRule.Direction.IN, Protocol.TCP,
                    srcIp, srcPort, ctx.publicIp, publicPort);
            if (!d.allowed) {
                Log.fw(tag, "TU CHOI vao cong " + publicPort + " (" + d.reason + ")");
                ctx.firewall.recordDeniedProbe(srcIp, publicPort);
                return;
            }
            Log.fw(tag, "CHO PHEP vao cong " + publicPort + " (" + d.reason + ")");

            inside = new Socket();
            inside.connect(new InetSocketAddress(internalIp, internalPort), ctx.connectTimeoutMs);

            entry = ctx.nat.registerStatic(Protocol.TCP, internalIp, internalPort,
                    publicPort, srcIp, srcPort);
            final Socket in = inside, out = outside;
            entry.setCloser(() -> {
                TcpNatHandler.closeQuietly(in);
                TcpNatHandler.closeQuietly(out);
            });

            Log.info(tag, String.format("CHUYEN TIEP VAO  %s:%d -> %s:%d -> %s:%d",
                    srcIp, srcPort, ctx.publicIp, publicPort, internalIp, internalPort));

            Thread a = pipe(outside.getInputStream(), inside.getOutputStream(), entry, false, tag);
            Thread b = pipe(inside.getInputStream(), outside.getOutputStream(), entry, true, tag);
            a.join();
            b.join();

        } catch (Exception e) {
            Log.error(tag, "Loi chuyen tiep: " + e.getMessage());
        } finally {
            TcpNatHandler.closeQuietly(inside);
            TcpNatHandler.closeQuietly(outside);
            if (entry != null) ctx.nat.release(entry);
        }
    }

    private Thread pipe(InputStream in, OutputStream out, NatEntry entry,
                        boolean outward, String tag) {
        Thread t = new Thread(() -> {
            byte[] buf = new byte[ctx.bufferSize];
            try {
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                    out.flush();
                    if (outward) entry.addOut(n);
                    else entry.addIn(n);
                    Log.fwd(tag, (outward ? "LAN->NET " : "NET->LAN ") + n + " byte");
                }
            } catch (IOException ignored) {
            } finally {
                entry.closeResources();
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }

    public void stop() {
        running = false;
        try {
            if (server != null) server.close();
        } catch (IOException ignored) {
        }
    }
}
