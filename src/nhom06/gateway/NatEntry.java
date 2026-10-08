package nhom06.gateway;

import nhom06.common.Protocol;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Một dòng trong bảng NAT/PAT:
 *   (IP nội bộ, cổng nội bộ, IP đích, cổng đích)  <->  (IP công cộng, cổng công khai)
 *
 * Khoá ánh xạ dùng đủ 5 thành phần (protocol + 4 địa chỉ) giống NAPT thực tế,
 * nhờ đó cùng một Client có thể mở nhiều phiên tới nhiều đích khác nhau.
 */
public class NatEntry {

    public enum State { ACTIVE, CLOSING, CLOSED }

    public final Protocol protocol;
    public final String internalIp;
    public final int internalPort;
    public final String publicIp;
    public final int publicPort;
    public final String destIp;
    public final int destPort;
    public final long createdAt;
    /** true = ánh xạ tĩnh do Port Forwarding tạo ra, không bị timeout thu hồi. */
    public final boolean staticMapping;

    private volatile long lastActivity;
    private volatile State state = State.ACTIVE;
    private final AtomicLong bytesOut = new AtomicLong();  // LAN -> Internet
    private final AtomicLong bytesIn = new AtomicLong();   // Internet -> LAN

    /** Hành động đóng tài nguyên (socket) khi ánh xạ bị thu hồi. */
    private volatile Runnable closer;

    public NatEntry(Protocol protocol, String internalIp, int internalPort,
                    String publicIp, int publicPort,
                    String destIp, int destPort, boolean staticMapping) {
        this.protocol = protocol;
        this.internalIp = internalIp;
        this.internalPort = internalPort;
        this.publicIp = publicIp;
        this.publicPort = publicPort;
        this.destIp = destIp;
        this.destPort = destPort;
        this.staticMapping = staticMapping;
        this.createdAt = System.currentTimeMillis();
        this.lastActivity = this.createdAt;
    }

    public void touch() {
        lastActivity = System.currentTimeMillis();
    }

    public long lastActivity()      { return lastActivity; }
    public long idleMillis()        { return System.currentTimeMillis() - lastActivity; }
    public State state()            { return state; }
    public void state(State s)      { this.state = s; }
    public long bytesOut()          { return bytesOut.get(); }
    public long bytesIn()           { return bytesIn.get(); }
    public void addOut(long n)      { bytesOut.addAndGet(n); touch(); }
    public void addIn(long n)       { bytesIn.addAndGet(n); touch(); }
    public void setCloser(Runnable r) { this.closer = r; }

    public void closeResources() {
        Runnable r = closer;
        if (r != null) {
            try {
                r.run();
            } catch (Exception ignored) {
            }
        }
    }

    public String internalSocket() { return internalIp + ":" + internalPort; }
    public String publicSocket()   { return publicIp + ":" + publicPort; }
    public String destSocket()     { return destIp + ":" + destPort; }

    /** Khoá tra cứu theo chiều đi (LAN -> Internet). */
    public String key() {
        return key(protocol, internalIp, internalPort, destIp, destPort);
    }

    public static String key(Protocol p, String iIp, int iPort, String dIp, int dPort) {
        return p + "|" + iIp + ":" + iPort + "|" + dIp + ":" + dPort;
    }

    @Override
    public String toString() {
        return String.format("%-5s %-21s -> %-21s => %-21s %6ds %8d/%-8d %s%s",
                protocol, internalSocket(), publicSocket(), destSocket(),
                idleMillis() / 1000, bytesOut(), bytesIn(), state,
                staticMapping ? " (STATIC)" : "");
    }
}
