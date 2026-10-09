package nhom06.gateway;

import nhom06.common.Log;
import nhom06.common.Protocol;
import nhom06.common.Tunnel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.net.SocketTimeoutException;
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
 *   5. Chuyển tiếp dữ liệu hai chiều bằng hai luồng con, theo dõi trạng thái TCP:
 *        - Một phía gửi FIN (read() trả về -1): chuyển tiếp FIN sang phía kia bằng
 *          shutdownOutput() nhưng VẪN giữ chiều ngược lại (TCP half-close).
 *        - Lỗi / RST: huỷ cả hai chiều ngay lập tức.
 *   6. Khi cả hai chiều kết thúc -> thu hồi ánh xạ, trả cổng về pool.
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
            int destPort;
            try {
                destPort = Integer.parseInt(t[3]);
            } catch (NumberFormatException e) {
                write(cOut, Tunnel.deny("Cong dich khong hop le"));
                return;
            }
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
            String lastError = "";
            for (int attempt = 0; attempt < MAX_BIND_RETRY && outbound == null; attempt++) {
                NatTable.Allocation a = ctx.nat.allocate(Protocol.TCP, cIp, cPort, destIp, destPort, failedPort);
                if (!a.ok()) {
                    write(cOut, Tunnel.busy(a.error));
                    return;
                }
                entry = a.entry;
                Socket s = new Socket();
                try {
                    s.setReuseAddress(true);
                    s.bind(new InetSocketAddress(ctx.publicIp, entry.publicPort));
                    s.connect(new InetSocketAddress(destIp, destPort), ctx.connectTimeoutMs);
                    outbound = s;
                } catch (IOException ex) {
                    closeQuietly(s);
                    lastError = ex.getMessage();
                    failedPort = entry.publicPort;
                    ctx.nat.release(entry);
                    entry = null;
                    // Đích không phản hồi -> thử cổng khác cũng vô ích
                    if (ex instanceof ConnectException || ex instanceof SocketTimeoutException
                            || ex instanceof NoRouteToHostException) break;
                    // Còn lại (cổng bị OS giữ, TIME_WAIT...) -> thử cổng công khai khác
                }
            }
            if (outbound == null) {
                write(cOut, Tunnel.busy("Khong ket noi duoc " + destIp + ":" + destPort + " - " + lastError));
                Log.error(tag, "That bai khi ket noi " + destIp + ":" + destPort + " - " + lastError);
                return;
            }

            final NatEntry e = entry;
            final Socket ob = outbound;
            e.state(NatEntry.State.ESTABLISHED);
            e.setCloser(() -> {
                closeQuietly(ob);
                closeQuietly(clientSocket);
            });

            // --- 4. Báo cho Client biết nó "ra Internet" bằng địa chỉ nào ---
            write(cOut, Tunnel.ok(e.publicIp, e.publicPort));
            Log.info(tag, String.format("MO PHIEN  %s:%d --[NAT]--> %s:%d --> %s:%d  (ESTABLISHED)",
                    cIp, cPort, e.publicIp, e.publicPort, destIp, destPort));

            // --- 5. Chuyển tiếp hai chiều ---
            CountDownLatch done = new CountDownLatch(2);
            ctx.pool.execute(new Relay(clientSocket, ob, e, true, tag, done));
            ctx.pool.execute(new Relay(ob, clientSocket, e, false, tag, done));
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

    /**
     * Luồng sao chép byte MỘT chiều, đồng thời cập nhật thống kê và trạng thái TCP.
     *
     * Kết thúc bình thường (read() == -1) nghĩa là phía nguồn đã gửi FIN. Gateway
     * chuyển tiếp FIN sang phía đích bằng shutdownOutput() nhưng KHÔNG đóng socket,
     * để chiều ngược lại vẫn truyền được dữ liệu (half-close, RFC 793).
     */
    private class Relay implements Runnable {
        private final Socket src;
        private final Socket dst;
        private final NatEntry entry;
        private final boolean outbound;   // true: LAN -> Internet
        private final String tag;
        private final CountDownLatch done;

        Relay(Socket src, Socket dst, NatEntry entry,
              boolean outbound, String tag, CountDownLatch done) {
            this.src = src;
            this.dst = dst;
            this.entry = entry;
            this.outbound = outbound;
            this.tag = tag;
            this.done = done;
        }

        @Override
        public void run() {
            byte[] buf = new byte[ctx.bufferSize];
            String from = outbound ? "LAN" : "Internet";
            String to = outbound ? "Internet" : "LAN";
            try {
                InputStream in = src.getInputStream();
                OutputStream out = dst.getOutputStream();
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                    out.flush();
                    if (outbound) entry.addOut(n);
                    else entry.addIn(n);
                    Log.fwd(tag, (outbound ? "LAN->NET " : "NET->LAN ") + n + " byte  ["
                            + entry.internalSocket() + " <-> " + entry.publicSocket() + "]");
                }
                // FIN từ phía nguồn -> chuyển tiếp FIN, giữ chiều còn lại
                NatEntry.State st = entry.onFin(outbound);
                Log.info(tag, "FIN tu " + from + " -> chuyen FIN sang " + to
                        + " (half-close). Trang thai: " + st);
                try {
                    dst.shutdownOutput();
                } catch (IOException ignored) {
                    // phía đích đã đóng hẳn
                }
            } catch (IOException ex) {
                // RST, lỗi mạng, hoặc socket bị đóng chủ động (timeout / chiều kia lỗi)
                if (!entry.isExpired() && entry.state() != NatEntry.State.CLOSED
                        && entry.state() != NatEntry.State.RESET) {
                    entry.markReset();
                    Log.info(tag, "RST/loi o chieu " + from + "->" + to + " (" + ex.getMessage()
                            + ") -> huy ca hai chieu");
                }
                entry.closeResources();
            } finally {
                done.countDown();
            }
        }
    }
}
