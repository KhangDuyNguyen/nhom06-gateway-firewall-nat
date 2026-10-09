package nhom06.gateway;

import nhom06.common.Protocol;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Một dòng trong bảng NAT/PAT:
 *   (IP nội bộ, cổng nội bộ) [+ đích]  <->  (IP công cộng, cổng công khai)
 *
 * Với TCP, mỗi ánh xạ còn theo dõi TRẠNG THÁI KẾT NỐI giống connection tracking của
 * Router/Linux (conntrack):
 *
 *   SYN_SENT ──connect OK──► ESTABLISHED ──FIN từ LAN──► FIN_LAN ─┐
 *                                  │                               ├─FIN chiều còn lại─► TIME_WAIT ─► CLOSED
 *                                  └──────FIN từ Internet──► FIN_WAN ┘
 *                    (lỗi/RST ở bất kỳ đâu) ──────────────────────────────► RESET ─► CLOSED
 *
 * Trạng thái "chuyển tiếp" (SYN_SENT, FIN_*, TIME_WAIT) dùng timeout NGẮN hơn ESTABLISHED,
 * đúng như cách Router thật giải phóng bảng NAT nhanh khi kết nối đang đóng.
 */
public class NatEntry {

    public enum State { ACTIVE, SYN_SENT, ESTABLISHED, FIN_LAN, FIN_WAN, TIME_WAIT, RESET, CLOSED }

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
    /** Kiểu NAT tại thời điểm tạo ánh xạ (quyết định hành vi lọc chiều về). */
    public final NatMode mode;

    /** Khoá trong bảng NAT (do NatTable gán, dùng để gỡ O(1)). */
    volatile String mapKey;
    /** true nếu ánh xạ đang được tính vào giới hạn số phiên của IP nội bộ. */
    volatile boolean countedForIp;

    private volatile long lastActivity;
    private volatile State state;
    private volatile boolean finFromLan;
    private volatile boolean finFromWan;
    private volatile boolean expired;
    private final AtomicLong bytesOut = new AtomicLong();  // LAN -> Internet
    private final AtomicLong bytesIn = new AtomicLong();   // Internet -> LAN

    /** Các đích (IP:cổng) mà Client đã gửi tới qua ánh xạ này — dùng cho bộ lọc chiều về. */
    private final Set<String> peers = ConcurrentHashMap.newKeySet();
    private final Set<String> peerIps = ConcurrentHashMap.newKeySet();

    /** Hành động đóng tài nguyên (socket) khi ánh xạ bị thu hồi. */
    private volatile Runnable closer;

    public NatEntry(Protocol protocol, String internalIp, int internalPort,
                    String publicIp, int publicPort,
                    String destIp, int destPort, boolean staticMapping) {
        this(protocol, internalIp, internalPort, publicIp, publicPort,
                destIp, destPort, staticMapping, NatMode.SYMMETRIC);
    }

    public NatEntry(Protocol protocol, String internalIp, int internalPort,
                    String publicIp, int publicPort,
                    String destIp, int destPort, boolean staticMapping, NatMode mode) {
        this.protocol = protocol;
        this.internalIp = internalIp;
        this.internalPort = internalPort;
        this.publicIp = publicIp;
        this.publicPort = publicPort;
        this.destIp = destIp;
        this.destPort = destPort;
        this.staticMapping = staticMapping;
        this.mode = mode;
        this.createdAt = System.currentTimeMillis();
        this.lastActivity = this.createdAt;
        if (staticMapping) state = State.ESTABLISHED;
        else state = (protocol == Protocol.TCP) ? State.SYN_SENT : State.ACTIVE;
        addPeer(destIp, destPort);
    }

    // ------------------------------------------------------------------ hoạt động
    public void touch()              { lastActivity = System.currentTimeMillis(); }
    public long lastActivity()       { return lastActivity; }
    public long idleMillis()         { return System.currentTimeMillis() - lastActivity; }
    public long bytesOut()           { return bytesOut.get(); }
    public long bytesIn()            { return bytesIn.get(); }
    public void addOut(long n)       { bytesOut.addAndGet(n); touch(); }
    public void addIn(long n)        { bytesIn.addAndGet(n); touch(); }

    // ------------------------------------------------------------------ trạng thái
    public State state()             { return state; }
    public void state(State s)       { this.state = s; }

    /** Ghi nhận gói FIN (một chiều kết thúc gửi). Trả về trạng thái mới. */
    public synchronized State onFin(boolean fromLan) {
        if (fromLan) finFromLan = true;
        else finFromWan = true;
        if (state == State.RESET || state == State.CLOSED) return state;
        if (finFromLan && finFromWan) state = State.TIME_WAIT;
        else state = fromLan ? State.FIN_LAN : State.FIN_WAN;
        touch();
        return state;
    }

    public synchronized void markReset() {
        if (state != State.CLOSED) state = State.RESET;
    }

    /** true khi ánh xạ đang ở trạng thái chuyển tiếp (dùng timeout ngắn). */
    public boolean isTransitory() {
        State s = state;
        return s == State.SYN_SENT || s == State.FIN_LAN || s == State.FIN_WAN
                || s == State.TIME_WAIT || s == State.RESET;
    }

    /** Đánh dấu ánh xạ bị NatCleaner thu hồi do hết hạn (không phải lỗi/RST). */
    public void expire()             { expired = true; }
    public boolean isExpired()       { return expired; }

    // ------------------------------------------------------------------ đích đã liên lạc
    public void addPeer(String ip, int port) {
        if (ip == null || port <= 0) return;
        peers.add(ip + ":" + port);
        peerIps.add(ip);
    }

    public boolean hasContactedPeer(String ip, int port) { return peers.contains(ip + ":" + port); }
    public boolean hasContactedIp(String ip)             { return peerIps.contains(ip); }
    public int peerCount()                               { return peers.size(); }

    // ------------------------------------------------------------------ tài nguyên
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

    // ------------------------------------------------------------------ hiển thị
    public String internalSocket() { return internalIp + ":" + internalPort; }
    public String publicSocket()   { return publicIp + ":" + publicPort; }
    public String destSocket()     { return destIp + ":" + destPort; }

    /** Đích hiển thị; với NAT kiểu cone có thể có nhiều đích dùng chung một ánh xạ. */
    public String destDisplay() {
        int n = peerCount();
        return (n > 1) ? destSocket() + " (+" + (n - 1) + ")" : destSocket();
    }

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
                protocol, internalSocket(), publicSocket(), destDisplay(),
                idleMillis() / 1000, bytesOut(), bytesIn(), state,
                staticMapping ? " (STATIC)" : (protocol == Protocol.UDP ? " [" + mode.label + "]" : ""));
    }
}
