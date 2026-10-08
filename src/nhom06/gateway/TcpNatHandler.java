package nhom06.gateway;

import nhom06.common.Log;
import nhom06.common.Protocol;
import nhom06.common.Tunnel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;

/**
 * Xử lý MỘT phiên TCP từ Client nội bộ.
 * Mỗi kết nối được Gateway giao cho một luồng riêng lấy từ thread pool.
 *
 * Trình tự:
 *   1. Đọc header CONNECT để biết đích mà Client muốn ra.
 *   2. Hỏi Firewall (chiều OUT). Bị chặn -> trả 403 và đóng kết nối.
 *   3. Cấp phát ánh xạ trong bảng NAT và mở socket ra ngoài, BIND vào
 *      (IP công cộng, cổng công khai) đã cấp -> External Server chỉ nhìn thấy
 *      địa chỉ công cộng, đúng bản chất của NAT/PAT.
 *   4. Trả 200 OK kèm địa chỉ công cộng cho Client (phục vụ mục đích minh hoạ).
 *   5. Chuyển tiếp dữ liệu hai chiều bằng hai luồng con.
 *   6. Khi phiên kết thúc -> thu hồi ánh xạ, trả cổng về pool.
 */
public class TcpNatHandler implements Runnable {

    private static final int MAX_BIND_RETRY = 5;

    private final Socket clientSocket;
    private final GatewayContext ctx;

    public TcpNatHandler(Socket clientSocket, GatewayContext ctx) {
        this.clientSocket = clientSocket;
        this.ctx = ctx;
    }

    @Override
    public void run() {
        String cIp = clientSocket.getInetAddress().getHostAddress();
        int cPort = clientSocket.getPort();
        String tag = "TCP " + cIp + ":" + cPort;
        NatEntry entry = null;
        Socket outbound = null;

        try {
            clientSocket.setSoTimeout(ctx.headerTimeoutMs);
            InputStream cIn = clientSocket.getInputStream();
            OutputStream cOut = clientSocket.getOutputStream();

            // --- 1. Đọc yêu cầu CONNECT ---
            String header = Tunnel.readLine(cIn);
            if (header == null) {
                Log.error(tag, "Client dong ket noi truoc khi gui header.");
                return;
            }
            String[] t = Tunnel.tokens(header);
            if (t.length < 4 || !t[1].equalsIgnoreCase("CONNECT")) {
                write(cOut, Tunnel.deny("Header khong hop le"));
                Log.error(tag, "Header sai dinh dang: " + header);
                return;
            }
            String destIp = t[2];
            int destPort = Integer.parseInt(t[3]);
            clientSocket.setSoTimeout(0); // bỏ timeout, chuyển sang giai đoạn relay

            // --- 2. Firewall chiều đi ---
            Firewall.Decision d = ctx.firewall.check(FirewallRule.Direction.OUT, Protocol.TCP,
                    cIp, cPort, destIp, destPort);
            if (!d.allowed) {
                Log.fw(tag, "TU CHOI ra " + destIp + ":" + destPort + " (" + d.reason + ")");
                write(cOut, Tunnel.deny("Bi firewall chan: " + d.reason));
                return;
            }
            Log.fw(tag, "CHO PHEP ra " + destIp + ":" + destPort + " (" + d.reason + ")");

            // --- 3. Cấp phát NAT + mở kết nối ra ngoài ---
            Integer failedPort = null;
            for (int attempt = 0; attempt < MAX_BIND_RETRY && outbound == null; attempt++) {
                entry = ctx.nat.allocate(Protocol.TCP, cIp, cPort, destIp, destPort, failedPort);
                if (entry == null) {
                    write(cOut, Tunnel.busy("Het cong NAT"));
                    return;
                }
                try {
                    Socket s = new Socket();
                    s.setReuseAddress(true);
                    s.bind(new InetSocketAddress(ctx.publicIp, entry.publicPort));
                    s.connect(new InetSocketAddress(destIp, destPort), ctx.connectTimeoutMs);
                    outbound = s;
                } catch (IOException bindErr) {
                    // Cổng đang bị hệ điều hành giữ (TIME_WAIT) -> thu hồi và thử cổng khác
                    failedPort = entry.publicPort;
                    ctx.nat.release(entry);
                    entry = null;
                    if (attempt == MAX_BIND_RETRY - 1) {
                        write(cOut, Tunnel.busy("Khong mo duoc ket noi ra ngoai: " + bindErr.getMessage()));
                        Log.error(tag, "That bai khi ket noi " + destIp + ":" + destPort + " - " + bindErr.getMessage());
                        return;
                    }
                }
            }

            final NatEntry e = entry;
            final Socket ob = outbound;
            e.setCloser(() -> {
                closeQuietly(ob);
                closeQuietly(clientSocket);
            });

            // --- 4. Báo cho Client biết nó "ra Internet" bằng địa chỉ nào ---
            write(cOut, Tunnel.ok(e.publicIp, e.publicPort));
            Log.info(tag, String.format("MO PHIEN  %s:%d --[NAT]--> %s:%d --> %s:%d",
                    cIp, cPort, e.publicIp, e.publicPort, destIp, destPort));

            // --- 5. Chuyển tiếp hai chiều ---
            CountDownLatch done = new CountDownLatch(2);
            ctx.pool.execute(new Relay(cIn, ob.getOutputStream(), e, true, tag, done));
            ctx.pool.execute(new Relay(ob.getInputStream(), cOut, e, false, tag, done));
            done.await();

        } catch (Exception ex) {
            Log.error(tag, "Loi phien: " + ex.getMessage());
        } finally {
            closeQuietly(outbound);
            closeQuietly(clientSocket);
            if (entry != null) ctx.nat.release(entry);
            Log.info(tag, "DONG PHIEN");
        }
    }

    private void write(OutputStream out, String s) throws IOException {
        out.write(s.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    static void closeQuietly(Socket s) {
        if (s != null) {
            try {
                s.close();
            } catch (IOException ignored) {
            }
        }
    }

    /** Luồng sao chép byte một chiều, đồng thời cập nhật thống kê cho bảng NAT. */
    private class Relay implements Runnable {
        private final InputStream in;
        private final OutputStream out;
        private final NatEntry entry;
        private final boolean outbound;   // true: LAN -> Internet
        private final String tag;
        private final CountDownLatch done;

        Relay(InputStream in, OutputStream out, NatEntry entry,
              boolean outbound, String tag, CountDownLatch done) {
            this.in = in;
            this.out = out;
            this.entry = entry;
            this.outbound = outbound;
            this.tag = tag;
            this.done = done;
        }

        @Override
        public void run() {
            byte[] buf = new byte[ctx.bufferSize];
            try {
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                    out.flush();
                    if (outbound) entry.addOut(n);
                    else entry.addIn(n);
                    Log.fwd(tag, (outbound ? "LAN->NET " : "NET->LAN ") + n + " byte  ["
                            + entry.internalSocket() + " <-> " + entry.publicSocket() + "]");
                }
            } catch (IOException ignored) {
                // socket bị đóng: kết thúc bình thường
            } finally {
                entry.state(NatEntry.State.CLOSING);
                // đóng nửa còn lại để luồng ngược thoát khỏi read()
                entry.closeResources();
                done.countDown();
            }
        }
    }
}
