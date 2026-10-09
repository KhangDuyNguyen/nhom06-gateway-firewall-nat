package nhom06.gateway;

import nhom06.common.Log;
import nhom06.common.Protocol;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Tiểu trình chạy ngầm dọn dẹp bảng NAT (NAT Session Timeout).
 *
 * Định kỳ quét toàn bộ ánh xạ; ánh xạ nào im lặng quá ngưỡng sẽ bị đóng socket
 * và thu hồi cổng công khai về pool. Không có cơ chế này, bảng NAT sẽ phình ra
 * và dải cổng PAT cạn dần — đúng vấn đề của Router thật.
 *
 * Ba ngưỡng khác nhau, giống connection tracking của Linux:
 *   - TCP ESTABLISHED : dài (kết nối đang hoạt động bình thường)
 *   - TCP chuyển tiếp : ngắn (SYN_SENT, FIN_LAN, FIN_WAN, TIME_WAIT, RESET)
 *   - UDP             : trung bình, dựa hoàn toàn vào thời gian im lặng
 * Ánh xạ tĩnh (Port Forwarding) được bỏ qua.
 */
public class NatCleaner {

    private final NatTable nat;
    private final long tcpTimeoutMs;
    private final long udpTimeoutMs;
    private final long transitoryTimeoutMs;
    private final long intervalMs;
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "nat-cleaner");
                t.setDaemon(true);
                return t;
            });

    public NatCleaner(NatTable nat, long tcpTimeoutMs, long udpTimeoutMs,
                      long transitoryTimeoutMs, long intervalMs) {
        this.nat = nat;
        this.tcpTimeoutMs = tcpTimeoutMs;
        this.udpTimeoutMs = udpTimeoutMs;
        this.transitoryTimeoutMs = transitoryTimeoutMs;
        this.intervalMs = intervalMs;
    }

    public void start() {
        scheduler.scheduleAtFixedRate(this::sweep, intervalMs, intervalMs, TimeUnit.MILLISECONDS);
        Log.info("NAT-CLEANER", String.format(
                "Bat dau quet moi %.1fs (timeout TCP=%ds, TCP dang dong=%ds, UDP=%ds)",
                intervalMs / 1000.0, tcpTimeoutMs / 1000, transitoryTimeoutMs / 1000, udpTimeoutMs / 1000));
    }

    /** Ngưỡng timeout áp dụng cho một ánh xạ ở trạng thái hiện tại. */
    public long limitFor(NatEntry e) {
        if (e.protocol == Protocol.UDP) return udpTimeoutMs;
        return e.isTransitory() ? transitoryTimeoutMs : tcpTimeoutMs;
    }

    private void sweep() {
        try {
            List<NatEntry> all = nat.snapshot();
            int removed = 0;
            for (NatEntry e : all) {
                if (e.staticMapping) continue;
                boolean expired = e.idleMillis() > limitFor(e);
                boolean closed = e.state() == NatEntry.State.CLOSED;
                if (expired || closed) {
                    Log.nat("NAT-CLEANER", String.format("THU HOI do %s: %s (%s, %s) idle=%ds",
                            expired ? "TIMEOUT" : "ket noi da dong",
                            e.publicSocket(), e.protocol, e.state(), e.idleMillis() / 1000));
                    e.expire();
                    e.closeResources();
                    nat.release(e);
                    removed++;
                }
            }
            if (removed > 0) {
                Log.info("NAT-CLEANER", "Da thu hoi " + removed + " anh xa. Bang NAT con "
                        + nat.dynamicSize() + "/" + nat.capacity() + " muc.");
            }
        } catch (Exception e) {
            Log.error("NAT-CLEANER", "Loi khi quet: " + e.getMessage());
        }
    }

    public long tcpTimeoutMs()        { return tcpTimeoutMs; }
    public long udpTimeoutMs()        { return udpTimeoutMs; }
    public long transitoryTimeoutMs() { return transitoryTimeoutMs; }

    public void stop() {
        scheduler.shutdownNow();
    }
}
