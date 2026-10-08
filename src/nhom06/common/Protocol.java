package nhom06.common;

/**
 * Giao thức tầng 4 được Gateway hỗ trợ.
 * ANY chỉ dùng cho luật firewall (khớp mọi giao thức).
 */
public enum Protocol {
    TCP, UDP, ANY;

    public static Protocol parse(String s) {
        if (s == null) return ANY;
        s = s.trim().toUpperCase();
        if (s.equals("*")) return ANY;
        try {
            return Protocol.valueOf(s);
        } catch (IllegalArgumentException e) {
            return ANY;
        }
    }

    /** ANY khớp với mọi giao thức. */
    public boolean matches(Protocol other) {
        return this == ANY || other == ANY || this == other;
    }
}
