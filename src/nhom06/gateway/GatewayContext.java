package nhom06.gateway;

import java.util.concurrent.ExecutorService;

/**
 * Gói các thành phần dùng chung của Gateway để truyền cho các luồng xử lý
 * (bảng NAT, firewall, cấu hình mạng, pool luồng).
 */
public class GatewayContext {

    public final NatTable nat;
    public final Firewall firewall;
    public final String lanIp;
    public final String publicIp;
    public final ExecutorService pool;
    public final int bufferSize;
    public final int connectTimeoutMs;
    public final int headerTimeoutMs;

    private final java.util.concurrent.ConcurrentHashMap<String, Integer> qosLimits = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.ConcurrentHashMap<String, Long> qosWindowSec = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.atomic.AtomicLong> qosBytesSec = new java.util.concurrent.ConcurrentHashMap<>();

    public GatewayContext(NatTable nat, Firewall firewall, String lanIp, String publicIp,
                          ExecutorService pool, int bufferSize,
                          int connectTimeoutMs, int headerTimeoutMs) {
        this.nat = nat;
        this.firewall = firewall;
        this.lanIp = lanIp;
        this.publicIp = publicIp;
        this.pool = pool;
        this.bufferSize = bufferSize;
        this.connectTimeoutMs = connectTimeoutMs;
        this.headerTimeoutMs = headerTimeoutMs;
    }

    public void setQosLimit(String ip, int kbPerSec) {
        if (kbPerSec <= 0) qosLimits.remove(ip);
        else qosLimits.put(ip, kbPerSec * 1024);
    }

    public int getQosLimitKb(String ip) {
        int bytes = qosLimits.getOrDefault(ip, 0);
        return bytes / 1024;
    }

    public java.util.Map<String, Integer> qosLimitsKb() {
        java.util.Map<String, Integer> res = new java.util.HashMap<>();
        qosLimits.forEach((ip, bytes) -> res.put(ip, bytes / 1024));
        return res;
    }

    /** Điều tiết lưu lượng: chèn delay nhỏ nếu tốc độ vượt ngưỡng cấu hình trong giây hiện tại. */
    public void throttle(String ip, int bytes) {
        Integer limit = qosLimits.get(ip);
        if (limit == null || limit <= 0) return;
        long currentSec = System.currentTimeMillis() / 1000;
        Long win = qosWindowSec.get(ip);
        if (win == null || win != currentSec) {
            qosWindowSec.put(ip, currentSec);
            qosBytesSec.computeIfAbsent(ip, k -> new java.util.concurrent.atomic.AtomicLong()).set(0);
        }
        long curBytes = qosBytesSec.computeIfAbsent(ip, k -> new java.util.concurrent.atomic.AtomicLong()).addAndGet(bytes);
        if (curBytes > limit) {
            try {
                Thread.sleep(25);
            } catch (InterruptedException ignored) {}
        }
    }
}
