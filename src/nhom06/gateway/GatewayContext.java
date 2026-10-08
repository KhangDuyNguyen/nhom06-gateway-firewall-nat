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
}
