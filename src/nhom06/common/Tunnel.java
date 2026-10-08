package nhom06.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Giao thức điều khiển nhỏ giữa Client nội bộ và Gateway.
 *
 * Trong thực tế Router/NAT hoạt động ở tầng 3 nên hoàn toàn trong suốt: nó đọc
 * IP đích ngay trong phần header của gói tin. Java Socket chỉ làm việc ở tầng 4
 * trở lên và không cho phép sửa header IP, vì vậy Client phải "khai báo" địa chỉ
 * đích cho Gateway bằng một dòng header ngắn ở đầu phiên. Sau dòng header này,
 * mọi byte còn lại được chuyển tiếp nguyên trạng (raw relay) đúng như NAT thật.
 *
 * TCP:
 *   Client -> Gateway : "NAT/1.0 CONNECT <destIp> <destPort>\n"
 *   Gateway -> Client : "NAT/1.0 200 OK <publicIp> <publicPort>\n"
 *                     | "NAT/1.0 403 DENY <ly-do>\n"
 *                     | "NAT/1.0 503 BUSY <ly-do>\n"
 * UDP:
 *   Client  -> Gateway: "NAT/1.0 SEND <destIp> <destPort>\n" + <du lieu>
 *   Gateway -> Client : "NAT/1.0 FROM <srcIp> <srcPort>\n" + <du lieu>
 */
public final class Tunnel {

    public static final String VERSION = "NAT/1.0";
    public static final int MAX_HEADER = 256;

    private Tunnel() {
    }

    public static String connectRequest(String destIp, int destPort) {
        return VERSION + " CONNECT " + destIp + " " + destPort + "\n";
    }

    public static String sendHeader(String destIp, int destPort) {
        return VERSION + " SEND " + destIp + " " + destPort + "\n";
    }

    public static String fromHeader(String srcIp, int srcPort) {
        return VERSION + " FROM " + srcIp + " " + srcPort + "\n";
    }

    public static String ok(String publicIp, int publicPort) {
        return VERSION + " 200 OK " + publicIp + " " + publicPort + "\n";
    }

    public static String deny(String reason) {
        return VERSION + " 403 DENY " + reason + "\n";
    }

    public static String busy(String reason) {
        return VERSION + " 503 BUSY " + reason + "\n";
    }

    /**
     * Đọc một dòng header theo từng byte.
     * KHÔNG dùng BufferedReader vì bộ đệm của nó sẽ "nuốt" luôn phần dữ liệu
     * nhị phân phía sau header, làm hỏng quá trình chuyển tiếp.
     */
    public static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') break;
            if (b != '\r') buf.write(b);
            if (buf.size() > MAX_HEADER) throw new IOException("Header vuot qua " + MAX_HEADER + " byte");
        }
        if (buf.size() == 0 && b == -1) return null;
        return buf.toString(StandardCharsets.UTF_8.name());
    }

    /** Tách một dòng header thành các token. */
    public static String[] tokens(String line) {
        return line.trim().split("\\s+");
    }
}
