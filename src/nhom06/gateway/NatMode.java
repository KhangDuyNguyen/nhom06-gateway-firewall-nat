package nhom06.gateway;

/**
 * Kiểu NAT theo phân loại kinh điển (RFC 3489) và hành vi ánh xạ / lọc (RFC 4787).
 *
 * Hai câu hỏi quyết định một kiểu NAT:
 *  1. ÁNH XẠ (mapping): cùng một (IP, cổng) nội bộ gửi tới các đích KHÁC NHAU
 *     thì có dùng chung một cổng công khai không?
 *       - Symmetric: KHÔNG, mỗi đích một cổng công khai riêng.
 *       - Các kiểu "cone": CÓ, dùng chung (Endpoint-Independent Mapping).
 *  2. LỌC (filtering): gói tin từ Internet gửi vào cổng công khai được chấp nhận khi nào?
 *       - Full-cone            : mọi nguồn.
 *       - Restricted-cone      : nguồn có IP mà Client đã từng gửi tới.
 *       - Port-restricted-cone : nguồn có đúng (IP, cổng) mà Client đã từng gửi tới.
 *       - Symmetric            : giống Port-restricted (và ánh xạ riêng theo đích).
 *
 * Trong đồ án, kiểu NAT áp dụng cho UDP — đúng như thực tế, vì đây là yếu tố quyết định
 * khả năng kết nối P2P / VoIP / game (STUN, hole punching). Với TCP, mỗi phiên của Client
 * đã là một kết nối riêng tới Gateway nên luôn có ánh xạ riêng.
 */
public enum NatMode {

    SYMMETRIC("Symmetric",
            "Moi dich mot cong cong khai rieng; chi nhan goi tu dung (IP, cong) da gui toi"),
    FULL_CONE("Full-cone",
            "Dung chung mot cong cong khai cho moi dich; nhan goi tu MOI nguon ben ngoai"),
    RESTRICTED_CONE("Restricted-cone",
            "Dung chung cong cong khai; chi nhan goi tu IP da gui toi"),
    PORT_RESTRICTED_CONE("Port-restricted-cone",
            "Dung chung cong cong khai; chi nhan goi tu dung (IP, cong) da gui toi");

    public final String label;
    public final String description;

    NatMode(String label, String description) {
        this.label = label;
        this.description = description;
    }

    /** true: ánh xạ phụ thuộc đích (mỗi đích một cổng công khai). */
    public boolean destinationDependentMapping() {
        return this == SYMMETRIC;
    }

    /** Quyết định có cho gói tin từ (srcIp, srcPort) đi vào ánh xạ e hay không. */
    public boolean allowsInbound(NatEntry e, String srcIp, int srcPort) {
        switch (this) {
            case FULL_CONE:
                return true;
            case RESTRICTED_CONE:
                return e.hasContactedIp(srcIp);
            default:
                return e.hasContactedPeer(srcIp, srcPort);
        }
    }

    /** Nhận cả tên đầy đủ lẫn tên rút gọn: symmetric | full | restricted | port. */
    public static NatMode parse(String s) {
        if (s == null) return SYMMETRIC;
        String v = s.trim().toUpperCase().replace('-', '_');
        switch (v) {
            case "FULL":
            case "FULL_CONE":
                return FULL_CONE;
            case "RESTRICTED":
            case "RESTRICTED_CONE":
                return RESTRICTED_CONE;
            case "PORT":
            case "PORT_RESTRICTED":
            case "PORT_RESTRICTED_CONE":
                return PORT_RESTRICTED_CONE;
            default:
                return SYMMETRIC;
        }
    }
}
