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
 * Ngưỡng TCP thường dài hơn UDP vì TCP có trạng thái kết nối rõ ràng,
 * còn UDP phi kết nối nên phải dựa hoàn toàn vào thời gian im lặng.
 * Ánh xạ tĩnh (Port Forwarding) được bỏ qua.
 */
public class NatCleaner {

    private final NatTable nat;
    private final long tcpTimeoutMs;
    private final long udpTimeoutMs;
    private final long intervalMs;
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "nat-cleaner");
                t.setDaemon(true);
                return t;
            });

    public NatCleaner(NatTable nat, long tcpTimeoutMs, long udpTimeoutMs, long intervalMs) {
        this.nat = nat;
        this.tcpTimeoutMs = tcpTimeoutMs;
        this.udpTimeoutMs = udpTimeoutMs;
        this.intervalMs = intervalMs;
    }

    public void start() {
        scheduler.scheduleAtFixedRate(this::sweep, intervalMs, intervalMs, TimeUnit.MILLISECONDS);
        Log.info("NAT-CLEANER", String.format(
                "Bat dau quet moi %ds (timeout TCP=%ds, UDP=%ds)",
                intervalMs / 1000, tcpTimeoutMs / 1000, udpTimeoutMs / 1000));
    }

    private void sweep() {
        try {
            List<NatEntry> all = nat.snapshot();
            int removed = 0;
            for (NatEntry e : all) {
                if (e.staticMapping) continue;
                long limit = (e.protocol == Protocol.UDP) ? udpTimeoutMs : tcpTimeoutMs;
                boolean expired = e.idleMillis() > limit;
                boolean closed = e.state() == NatEntry.State.CLOSED;
                if (expired || closed) {
                    Log.nat("NAT-CLEANER", String.format("THU HOI do %s: %s (%s) idle=%ds",
                            expired ? "TIMEOUT" : "ket noi da dong",
                            e.publicSocket(), e.protocol, e.idleMillis() / 1000));
                    e.closeResources();
                    nat.release(e);
                    removed++;
                }
            }
            if (removed > 0) {
                Log.info("NAT-CLEANER", "Da thu hoi " + removed + " anh xa. Bang NAT con "
                        + nat.size() + "/" + nat.capacity() + " muc.");
            }
        } catch (Exception e) {
            Log.error("NAT-CLEANER", "Loi khi quet: " + e.getMessage());
        }
    }

    public void stop() {
        scheduler.shutdownNow();
    }
}
