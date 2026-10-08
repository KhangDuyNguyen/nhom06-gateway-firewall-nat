package nhom06.gateway;

import nhom06.common.Log;
import nhom06.common.Protocol;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bảng NAT/PAT của Gateway.
 *
 * Toàn bộ cấu trúc dùng ConcurrentHashMap để nhiều luồng xử lý Client có thể
 * tra cứu / ghi nhận song song mà không cần khoá toàn cục (tránh nghẽn cổ chai).
 *
 * Hai chỉ mục được duy trì song song:
 *   - byKey        : tra cứu theo chiều đi   (internal 5-tuple -> entry)
 *   - byPublicTcp/Udp : tra cứu theo chiều về (cổng công khai  -> entry)
 *
 * Việc cấp phát cổng dùng putIfAbsent() nên nguyên tử: hai luồng không bao giờ
 * được cấp cùng một cổng công khai.
 */
public class NatTable {

    private final ConcurrentHashMap<String, NatEntry> byKey = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Integer, NatEntry> byPublicTcp = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Integer, NatEntry> byPublicUdp = new ConcurrentHashMap<>();

    private final String publicIp;
    private final int portMin;
    private final int portMax;
    private final AtomicInteger cursor;

    private final AtomicLong totalAllocated = new AtomicLong();
    private final AtomicLong totalReleased = new AtomicLong();
    private final AtomicLong totalRejected = new AtomicLong();
    private volatile int peak = 0;

    public NatTable(String publicIp, int portMin, int portMax) {
        this.publicIp = publicIp;
        this.portMin = portMin;
        this.portMax = portMax;
        this.cursor = new AtomicInteger(portMin);
    }

    private ConcurrentHashMap<Integer, NatEntry> indexOf(Protocol p) {
        return (p == Protocol.UDP) ? byPublicUdp : byPublicTcp;
    }

    /** Lấy cổng tiếp theo trong dải, quay vòng khi chạm biên. */
    private int nextPort() {
        int size = portMax - portMin + 1;
        int raw = cursor.getAndIncrement();
        if (raw > Integer.MAX_VALUE - 1000) cursor.set(portMin);
        return portMin + Math.floorMod(raw - portMin, size);
    }

    /**
     * Cấp phát một ánh xạ mới. Trả về null nếu hết cổng trong dải (pool exhausted).
     * @param exclude cổng vừa thất bại khi bind ở tầng OS, sẽ bị bỏ qua (có thể null)
     */
    public NatEntry allocate(Protocol proto, String internalIp, int internalPort,
                             String destIp, int destPort, Integer exclude) {
        Map<Integer, NatEntry> index = indexOf(proto);
        int attempts = portMax - portMin + 1;

        for (int i = 0; i < attempts; i++) {
            int port = nextPort();
            if (exclude != null && exclude == port) continue;

            NatEntry entry = new NatEntry(proto, internalIp, internalPort,
                    publicIp, port, destIp, destPort, false);

            if (index.putIfAbsent(port, entry) == null) {
                byKey.put(entry.key(), entry);
                long now = totalAllocated.incrementAndGet();
                int cur = size();
                if (cur > peak) peak = cur;
                Log.nat("NAT-TABLE", String.format(
                        "CAP PHAT #%d  %s %s:%d  ->  %s:%d  (dich %s:%d)",
                        now, proto, internalIp, internalPort, publicIp, port, destIp, destPort));
                return entry;
            }
        }
        totalRejected.incrementAndGet();
        Log.error("NAT-TABLE", "Het cong trong dai PAT " + portMin + "-" + portMax
                + " -> tu choi phien tu " + internalIp + ":" + internalPort);
        return null;
    }

    /** Đăng ký một ánh xạ tĩnh (Port Forwarding). */
    public NatEntry registerStatic(Protocol proto, String internalIp, int internalPort,
                                   int publicPort, String destIp, int destPort) {
        NatEntry entry = new NatEntry(proto, internalIp, internalPort,
                publicIp, publicPort, destIp, destPort, true);
        indexOf(proto).put(publicPort, entry);
        byKey.put(entry.key() + "|static|" + System.nanoTime(), entry);
        return entry;
    }

    public NatEntry lookupOutbound(Protocol proto, String internalIp, int internalPort,
                                   String destIp, int destPort) {
        return byKey.get(NatEntry.key(proto, internalIp, internalPort, destIp, destPort));
    }

    /** Tra cứu chiều về: gói tin quay lại cổng công khai nào thì thuộc Client nào. */
    public NatEntry lookupInbound(Protocol proto, int publicPort) {
        return indexOf(proto).get(publicPort);
    }

    public void release(NatEntry entry) {
        if (entry == null) return;
        entry.state(NatEntry.State.CLOSED);
        boolean removed = indexOf(entry.protocol).remove(entry.publicPort, entry);
        byKey.values().remove(entry);
        if (!removed) return; totalReleased.incrementAndGet();
        Log.nat("NAT-TABLE", String.format(
                "THU HOI     %s %s -> %s  (gui %d B / nhan %d B, song %ds)",
                entry.protocol, entry.internalSocket(), entry.publicSocket(),
                entry.bytesOut(), entry.bytesIn(),
                (System.currentTimeMillis() - entry.createdAt) / 1000));
    }

    public List<NatEntry> snapshot() {
        List<NatEntry> list = new ArrayList<>();
        list.addAll(byPublicTcp.values());
        list.addAll(byPublicUdp.values());
        list.sort(Comparator.comparingInt(e -> e.publicPort));
        return list;
    }

    public int size() {
        return byPublicTcp.size() + byPublicUdp.size();
    }

    public int capacity()          { return portMax - portMin + 1; }
    public int portMin()           { return portMin; }
    public int portMax()           { return portMax; }
    public String publicIp()       { return publicIp; }
    public long totalAllocated()   { return totalAllocated.get(); }
    public long totalReleased()    { return totalReleased.get(); }
    public long totalRejected()    { return totalRejected.get(); }
    public int peak()              { return peak; }
}
