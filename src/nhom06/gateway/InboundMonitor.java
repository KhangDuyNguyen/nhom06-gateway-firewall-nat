package nhom06.gateway;

import nhom06.common.Log;
import nhom06.common.Protocol;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Giám sát các cổng công khai KHÔNG có dịch vụ đứng sau.
 *
 * Gateway vẫn mở socket trên những cổng này để "nhìn thấy" các nỗ lực kết nối
 * từ bên ngoài. Mọi kết nối tới đây đều bị Firewall từ chối và đóng ngay lập tức,
 * đồng thời được ghi nhận vào bộ phát hiện quét cổng để sinh cảnh báo an ninh.
 * (Tương đương hành vi "log & drop" của tường lửa thật.)
 */
public class InboundMonitor implements Runnable {

    private final GatewayContext ctx;
    private final int port;
    private ServerSocket server;
    private volatile boolean running = true;

    public InboundMonitor(GatewayContext ctx, int port) {
        this.ctx = ctx;
        this.port = port;
    }

    public void start() throws IOException {
        server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(ctx.publicIp, port), 20);
        Thread t = new Thread(this, "inbound-monitor-" + port);
        t.setDaemon(true);
        t.start();
    }

    @Override
    public void run() {
        while (running) {
            try (Socket s = server.accept()) {
                String srcIp = s.getInetAddress().getHostAddress();
                int srcPort = s.getPort();
                Firewall.Decision d = ctx.firewall.check(FirewallRule.Direction.IN, Protocol.TCP,
                        srcIp, srcPort, ctx.publicIp, port);
                if (d.allowed) {
                    Log.fw("MONITOR", "Ket noi vao cong " + port + " duoc phep nhung khong co dich vu -> dong.");
                } else {
                    Log.fw("MONITOR", "CHAN ket noi tu " + srcIp + ":" + srcPort
                            + " toi cong " + port + " (" + d.reason + ")");
                    ctx.firewall.recordDeniedProbe(srcIp, port);
                }
            } catch (IOException e) {
                if (running) Log.error("MONITOR", "Loi cong " + port + ": " + e.getMessage());
            }
        }
    }

    public int port() {
        return port;
    }

    public void stop() {
        running = false;
        try {
            if (server != null) server.close();
        } catch (IOException ignored) {
        }
    }
}
