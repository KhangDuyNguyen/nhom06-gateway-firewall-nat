package nhom06.gateway;

import nhom06.common.Log;
import nhom06.common.Protocol;
import nhom06.common.Tunnel;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PAT cho giao thức phi kết nối UDP.
 *
 * Vì UDP không có khái niệm "phiên", Gateway tự tạo phiên ảo: mỗi bộ
 * (IP Client, cổng Client, IP đích, cổng đích) được gán một DatagramSocket riêng
 * bind vào (IP công cộng, cổng công khai). Socket này vừa dùng để gửi ra ngoài,
 * vừa lắng nghe phản hồi để định tuyến ngược về đúng Client.
 * Phiên UDP được NatCleaner thu hồi sau một khoảng im lặng (idle timeout).
 */
public class UdpNatService implements Runnable {

    private final GatewayContext ctx;
    private final int lanPort;
    private final int bufferSize;
    private DatagramSocket lanSocket;
    /** cổng công khai -> socket phía Internet của phiên đó */
    private final ConcurrentHashMap<Integer, DatagramSocket> publicSockets = new ConcurrentHashMap<>();
    private volatile boolean running = true;

    public UdpNatService(GatewayContext ctx, int lanPort, int bufferSize) {
        this.ctx = ctx;
        this.lanPort = lanPort;
        this.bufferSize = bufferSize;
    }

    public void start() throws Exception {
        lanSocket = new DatagramSocket(new InetSocketAddress(ctx.lanIp, lanPort));
        Log.info("UDP-NAT", "Lang nghe UDP tai " + ctx.lanIp + ":" + lanPort);
        Thread t = new Thread(this, "udp-nat-lan");
        t.setDaemon(true);
        t.start();
    }

    @Override
    public void run() {
        byte[] buf = new byte[bufferSize];
        while (running) {
            try {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                lanSocket.receive(p);
                handleFromLan(p);
            } catch (Exception e) {
                if (running) Log.error("UDP-NAT", "Loi nhan goi: " + e.getMessage());
            }
        }
    }

    private void handleFromLan(DatagramPacket p) {
        String cIp = p.getAddress().getHostAddress();
        int cPort = p.getPort();
        String tag = "UDP " + cIp + ":" + cPort;

        // Tách header "NAT/1.0 SEND <ip> <port>\n" khỏi phần dữ liệu
        byte[] data = new byte[p.getLength()];
        System.arraycopy(p.getData(), p.getOffset(), data, 0, p.getLength());
        int nl = indexOf(data, (byte) '\n');
        if (nl < 0) {
            Log.error(tag, "Goi UDP thieu header SEND, bo qua.");
            return;
        }
        String header = new String(data, 0, nl, StandardCharsets.UTF_8).trim();
        byte[] payload = new byte[data.length - nl - 1];
        System.arraycopy(data, nl + 1, payload, 0, payload.length);

        String[] t = Tunnel.tokens(header);
        if (t.length < 4 || !t[1].equalsIgnoreCase("SEND")) {
            Log.error(tag, "Header UDP sai dinh dang: " + header);
            return;
        }
        String destIp = t[2];
        int destPort;
        try {
            destPort = Integer.parseInt(t[3]);
        } catch (NumberFormatException e) {
            Log.error(tag, "Cong dich khong hop le: " + t[3]);
            return;
        }

        NatEntry entry = ctx.nat.lookupOutbound(Protocol.UDP, cIp, cPort, destIp, destPort);

        if (entry == null) {
            Firewall.Decision d = ctx.firewall.check(FirewallRule.Direction.OUT, Protocol.UDP,
                    cIp, cPort, destIp, destPort);
            if (!d.allowed) {
                Log.fw(tag, "TU CHOI UDP ra " + destIp + ":" + destPort + " (" + d.reason + ")");
                return;
            }
            Log.fw(tag, "CHO PHEP UDP ra " + destIp + ":" + destPort + " (" + d.reason + ")");
            entry = openSession(cIp, cPort, destIp, destPort, p.getAddress());
            if (entry == null) return;
        }

        DatagramSocket ps = publicSockets.get(entry.publicPort);
        if (ps == null) return;
        try {
            DatagramPacket out = new DatagramPacket(payload, payload.length,
                    InetAddress.getByName(destIp), destPort);
            ps.send(out);
            entry.addOut(payload.length);
            Log.fwd(tag, "LAN->NET " + payload.length + " byte  [" + entry.internalSocket()
                    + " -> " + entry.publicSocket() + " -> " + destIp + ":" + destPort + "]");
        } catch (Exception e) {
            Log.error(tag, "Khong gui duoc goi UDP ra ngoai: " + e.getMessage());
        }
    }

    /** Tạo phiên UDP ảo: cấp cổng công khai + mở socket phía Internet. */
    private NatEntry openSession(String cIp, int cPort, String destIp, int destPort,
                                 InetAddress clientAddr) {
        Integer failed = null;
        for (int attempt = 0; attempt < 5; attempt++) {
            NatEntry e = ctx.nat.allocate(Protocol.UDP, cIp, cPort, destIp, destPort, failed);
            if (e == null) return null;
            try {
                DatagramSocket ps = new DatagramSocket(null);
                ps.setReuseAddress(true);
                ps.bind(new InetSocketAddress(ctx.publicIp, e.publicPort));
                publicSockets.put(e.publicPort, ps);
                e.setCloser(() -> {
                    publicSockets.remove(e.publicPort);
                    ps.close();
                });
                startReturnListener(ps, e, clientAddr, cPort);
                Log.info("UDP-NAT", String.format("MO PHIEN  %s:%d --[PAT]--> %s:%d --> %s:%d",
                        cIp, cPort, e.publicIp, e.publicPort, destIp, destPort));
                return e;
            } catch (Exception bindErr) {
                failed = e.publicPort;
                ctx.nat.release(e);
            }
        }
        return null;
    }

    /** Luồng lắng nghe phản hồi từ Internet và định tuyến ngược về Client. */
    private void startReturnListener(DatagramSocket ps, NatEntry entry,
                                     InetAddress clientAddr, int clientPort) {
        Thread t = new Thread(() -> {
            byte[] buf = new byte[bufferSize];
            while (!ps.isClosed()) {
                try {
                    DatagramPacket in = new DatagramPacket(buf, buf.length);
                    ps.receive(in);
                    String srcIp = in.getAddress().getHostAddress();
                    int srcPort = in.getPort();

                    // Kiểm tra chiều về: chỉ chấp nhận gói từ đúng đích của phiên (stateful)
                    if (!srcIp.equals(entry.destIp) || srcPort != entry.destPort) {
                        Log.fw("UDP-NAT", "CHAN goi UDP la tu " + srcIp + ":" + srcPort
                                + " toi cong cong khai " + entry.publicPort);
                        ctx.firewall.recordDeniedProbe(srcIp, entry.publicPort);
                        continue;
                    }

                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    bos.write(Tunnel.fromHeader(srcIp, srcPort).getBytes(StandardCharsets.UTF_8));
                    bos.write(in.getData(), in.getOffset(), in.getLength());
                    byte[] out = bos.toByteArray();

                    lanSocket.send(new DatagramPacket(out, out.length, clientAddr, clientPort));
                    entry.addIn(in.getLength());
                    Log.fwd("UDP-NAT", "NET->LAN " + in.getLength() + " byte  ["
                            + entry.publicSocket() + " -> " + entry.internalSocket() + "]");
                } catch (Exception e) {
                    if (!ps.isClosed()) Log.error("UDP-NAT", "Loi chieu ve: " + e.getMessage());
                    break;
                }
            }
        }, "udp-nat-return-" + entry.publicPort);
        t.setDaemon(true);
        t.start();
    }

    private static int indexOf(byte[] a, byte target) {
        for (int i = 0; i < a.length; i++) if (a[i] == target) return i;
        return -1;
    }

    public void stop() {
        running = false;
        if (lanSocket != null) lanSocket.close();
        publicSockets.values().forEach(DatagramSocket::close);
    }
}
