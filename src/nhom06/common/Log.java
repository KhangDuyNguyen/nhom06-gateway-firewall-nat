package nhom06.common;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.Deque;
import java.util.List;

/**
 * Bộ ghi nhật ký dùng chung: in ra console, ghi ra file và giữ lại
 * N bản ghi gần nhất trong bộ nhớ để lệnh "log" / "alerts" của console quản trị truy xuất.
 * Tất cả phương thức ghi đều đồng bộ (thread-safe) vì Gateway chạy đa luồng.
 */
public final class Log {

    public enum Level {
        INFO,   // sự kiện chung
        NAT,    // cấp phát / thu hồi ánh xạ NAT
        FWD,    // chuyển tiếp dữ liệu
        FW,     // quyết định của firewall
        ALERT,  // cảnh báo an ninh
        ERROR
    }

    private static final SimpleDateFormat TS = new SimpleDateFormat("HH:mm:ss.SSS");
    private static final int RING_SIZE = 500;
    private static final Deque<String> RING = new ArrayDeque<>(RING_SIZE);
    private static final Deque<String> ALERTS = new ArrayDeque<>(100);

    private static PrintWriter file;
    private static boolean verbose = true;

    private Log() {
    }

    public static synchronized void init(String filePath, boolean verboseMode) {
        verbose = verboseMode;
        try {
            File f = new File(filePath);
            if (f.getParentFile() != null) f.getParentFile().mkdirs();
            file = new PrintWriter(new FileWriter(f, true), true);
            file.println("===== Phien lam viec moi: " + new Date() + " =====");
        } catch (IOException e) {
            System.out.println("[LOG] Khong mo duoc file log: " + e.getMessage());
        }
    }

    public static synchronized void write(Level level, String tag, String msg) {
        String line = String.format("%s [%-5s][%-12s] %s",
                TS.format(new Date()), level, tag, msg);

        if (verbose || level != Level.FWD) {
            System.out.println(line);
        }
        if (file != null) file.println(line);

        if (RING.size() >= RING_SIZE) RING.removeFirst();
        RING.addLast(line);

        if (level == Level.ALERT) {
            if (ALERTS.size() >= 100) ALERTS.removeFirst();
            ALERTS.addLast(line);
        }
    }

    public static void info(String tag, String msg)  { write(Level.INFO, tag, msg); }
    public static void nat(String tag, String msg)   { write(Level.NAT, tag, msg); }
    public static void fwd(String tag, String msg)   { write(Level.FWD, tag, msg); }
    public static void fw(String tag, String msg)    { write(Level.FW, tag, msg); }
    public static void alert(String tag, String msg) { write(Level.ALERT, tag, "*** CANH BAO *** " + msg); }
    public static void error(String tag, String msg) { write(Level.ERROR, tag, msg); }

    public static synchronized List<String> recent(int n) {
        List<String> all = new ArrayList<>(RING);
        int from = Math.max(0, all.size() - n);
        return all.subList(from, all.size());
    }

    public static synchronized List<String> alerts() {
        return new ArrayList<>(ALERTS);
    }

    public static synchronized void setVerbose(boolean v) {
        verbose = v;
    }

    public static synchronized boolean isVerbose() {
        return verbose;
    }

    public static synchronized void close() {
        if (file != null) file.close();
    }
}
