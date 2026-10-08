package nhom06.gateway;

import nhom06.common.Protocol;

/**
 * Một luật lọc gói tin.
 *
 * Cú pháp trong file cấu hình (các trường cách nhau bởi khoảng trắng):
 *   ACTION DIRECTION PROTO SRC_IP SRC_PORT DST_IP DST_PORT   # ghi chu
 *
 *   ACTION    : ALLOW | DENY
 *   DIRECTION : OUT (LAN -> Internet) | IN (Internet -> LAN) | ANY | *
 *   PROTO     : TCP | UDP | ANY | *
 *   IP        : dia chi cu the (127.0.0.3), CIDR (192.168.1.0/24) hoac *
 *   PORT      : so cu the (80), dai (8000-8100) hoac *
 *
 * Ví dụ:  DENY OUT TCP * * * 23
 */
public class FirewallRule {

    public enum Action { ALLOW, DENY }
    public enum Direction { IN, OUT, ANY }

    public final Action action;
    public final Direction direction;
    public final Protocol protocol;
    public final String srcIpSpec;
    public final String srcPortSpec;
    public final String dstIpSpec;
    public final String dstPortSpec;
    public final int lineNumber;
    public final String raw;

    public FirewallRule(Action action, Direction direction, Protocol protocol,
                        String srcIpSpec, String srcPortSpec,
                        String dstIpSpec, String dstPortSpec,
                        int lineNumber, String raw) {
        this.action = action;
        this.direction = direction;
        this.protocol = protocol;
        this.srcIpSpec = srcIpSpec;
        this.srcPortSpec = srcPortSpec;
        this.dstIpSpec = dstIpSpec;
        this.dstPortSpec = dstPortSpec;
        this.lineNumber = lineNumber;
        this.raw = raw;
    }

    /** Phân tích một dòng luật; trả về null nếu dòng trống / ghi chú / sai cú pháp. */
    public static FirewallRule parse(String line, int lineNumber) {
        String clean = line;
        int hash = clean.indexOf('#');
        if (hash >= 0) clean = clean.substring(0, hash);
        clean = clean.trim();
        if (clean.isEmpty()) return null;

        String[] t = clean.split("\\s+");
        if (t.length < 7) {
            System.out.println("[FIREWALL] Bo qua dong " + lineNumber + " (thieu truong): " + line);
            return null;
        }
        try {
            Action a = Action.valueOf(t[0].toUpperCase());
            Direction d = t[1].equals("*") ? Direction.ANY : Direction.valueOf(t[1].toUpperCase());
            Protocol p = Protocol.parse(t[2]);
            return new FirewallRule(a, d, p, t[3], t[4], t[5], t[6], lineNumber, clean);
        } catch (IllegalArgumentException e) {
            System.out.println("[FIREWALL] Bo qua dong " + lineNumber + " (sai cu phap): " + line);
            return null;
        }
    }

    public boolean matches(Direction dir, Protocol proto,
                           String srcIp, int srcPort, String dstIp, int dstPort) {
        if (direction != Direction.ANY && direction != dir) return false;
        if (!protocol.matches(proto)) return false;
        if (!ipMatches(srcIpSpec, srcIp)) return false;
        if (!portMatches(srcPortSpec, srcPort)) return false;
        if (!ipMatches(dstIpSpec, dstIp)) return false;
        return portMatches(dstPortSpec, dstPort);
    }

    /** Hỗ trợ '*', địa chỉ chính xác và CIDR a.b.c.d/n. */
    public static boolean ipMatches(String spec, String ip) {
        if (spec == null || spec.equals("*") || spec.equalsIgnoreCase("ANY")) return true;
        if (ip == null) return false;
        if (!spec.contains("/")) return spec.equals(ip);

        String[] parts = spec.split("/");
        try {
            long net = toLong(parts[0]);
            int bits = Integer.parseInt(parts[1]);
            long mask = (bits == 0) ? 0L : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
            return (toLong(ip) & mask) == (net & mask);
        } catch (Exception e) {
            return false;
        }
    }

    /** Hỗ trợ '*', số cụ thể và dải min-max. */
    public static boolean portMatches(String spec, int port) {
        if (spec == null || spec.equals("*") || spec.equalsIgnoreCase("ANY")) return true;
        try {
            if (spec.contains("-")) {
                String[] r = spec.split("-");
                int lo = Integer.parseInt(r[0].trim());
                int hi = Integer.parseInt(r[1].trim());
                return port >= lo && port <= hi;
            }
            return port == Integer.parseInt(spec.trim());
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static long toLong(String ip) {
        String[] o = ip.split("\\.");
        if (o.length != 4) throw new IllegalArgumentException("IP khong hop le: " + ip);
        long v = 0;
        for (String s : o) v = (v << 8) | (Integer.parseInt(s.trim()) & 0xFF);
        return v;
    }

    @Override
    public String toString() {
        return String.format("#%-3d %-5s %-3s %-4s src=%s:%s dst=%s:%s",
                lineNumber, action, direction, protocol,
                srcIpSpec, srcPortSpec, dstIpSpec, dstPortSpec);
    }
}
