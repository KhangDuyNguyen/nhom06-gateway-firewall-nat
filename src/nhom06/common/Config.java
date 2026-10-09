package nhom06.common;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

/**
 * Đọc cấu hình từ file .properties (UTF-8).
 * Nếu thiếu file hoặc thiếu key thì dùng giá trị mặc định truyền vào.
 */
public class Config {

    private final Properties props = new Properties();
    private final String path;

    public Config(String path) {
        this.path = path;
        try (InputStream in = new FileInputStream(path)) {
            props.load(new InputStreamReader(in, StandardCharsets.UTF_8));
            System.out.println("[CONFIG] Da nap cau hinh tu: " + path);
        } catch (IOException e) {
            System.out.println("[CONFIG] Khong doc duoc '" + path + "' -> dung gia tri mac dinh.");
        }
    }

    /** Tao cau hinh trong bo nho (dung cho bo kiem thu tu dong). */
    public Config(Properties source) {
        this.path = "(in-memory)";
        props.putAll(source);
    }

    public String getPath() {
        return path;
    }

    public String get(String key, String def) {
        String v = props.getProperty(key);
        return (v == null || v.trim().isEmpty()) ? def : v.trim();
    }

    public int getInt(String key, int def) {
        try {
            return Integer.parseInt(get(key, String.valueOf(def)));
        } catch (NumberFormatException e) {
            return def;
        }
    }

    public long getLong(String key, long def) {
        try {
            return Long.parseLong(get(key, String.valueOf(def)));
        } catch (NumberFormatException e) {
            return def;
        }
    }

    public boolean getBool(String key, boolean def) {
        return Boolean.parseBoolean(get(key, String.valueOf(def)));
    }

    /** Danh sách số nguyên phân tách bởi dấu phẩy, ví dụ "8023,8445,8139". */
    public List<Integer> getIntList(String key, String def) {
        List<Integer> out = new ArrayList<>();
        String raw = get(key, def);
        if (raw.isEmpty()) return out;
        for (String part : raw.split(",")) {
            part = part.trim();
            if (part.isEmpty()) continue;
            try {
                out.add(Integer.parseInt(part));
            } catch (NumberFormatException ignored) {
            }
        }
        return out;
    }

    /**
     * Lấy toàn bộ key có cùng tiền tố, sắp xếp theo tên key.
     * Dùng cho các luật Port Forwarding: portforward.1, portforward.2, ...
     */
    public Map<String, String> getByPrefix(String prefix) {
        Map<String, String> out = new TreeMap<>();
        for (String name : props.stringPropertyNames()) {
            if (name.startsWith(prefix)) {
                out.put(name, props.getProperty(name).trim());
            }
        }
        return out;
    }
}
