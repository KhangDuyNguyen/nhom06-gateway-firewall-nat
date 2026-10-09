# NHÓM 06 — Mô phỏng Gateway Firewall NAT/PAT

**Môn:** Lập trình mạng — Lớp 23DTHA5
**Đề tài:** Xây dựng ứng dụng mô phỏng Firewall Cổng giao tiếp (Gateway Firewall) sử dụng kỹ thuật NAT/PAT
**Ngôn ngữ:** Java thuần (`java.net`, `com.sun.net.httpserver` có sẵn trong JDK), không dùng thư viện ngoài

### Bảng đóng góp của thành viên

| MSSV | Họ và Tên | Công việc đã thực hiện | Merge Requests |
|------|-----------|------------------------|----------------|
| 2380600985 | Nguyễn Duy Khang (nhóm trưởng) | Lõi NAT: bảng NAT/PAT, cấp phát cổng, kiểu NAT, timeout, GatewayServer | (điền số PR, ví dụ #1, #5) |
| 2380600440 | Nguyễn Hữu Đạt | Chuyển tiếp TCP/UDP, half-close, đa luồng | |
| 2380614779 | Trần Xuân Dưỡng | Tường lửa, Port Forwarding, giám sát và cảnh báo quét cổng | |
| 2380600744 | Trần Huy Hoàng | Client, External Server, web dashboard, bộ kiểm thử | |

### Quy trình làm việc nhóm (theo quy định học phần)

- `git config --global user.name "MSSV_HoVaTen"` và email sinh viên, mỗi người dùng tài khoản của mình.
- Mỗi đầu việc là một Issue, gán cho đúng 1 người, có nhãn và mốc tuần.
- Nhánh `main` được khoá; làm trên nhánh `feature/<MSSV>-issue-<số>-<tên-ngắn>`.
- Commit theo Conventional Commits: `feat: ...`, `fix: ...`, `refactor: ...`, `docs: ...`.
- Pull Request có mô tả và ảnh chụp kết quả; ít nhất 1 thành viên khác duyệt (không tự duyệt).


---

## 1. Chạy nhanh

Yêu cầu: JDK 17 trở lên (`java -version`).

**Windows, một lần nhấp đúp:** `scripts\demo-all.bat`
Script tự biên dịch, mở 4 cửa sổ (External Server, Internal Service, Gateway, Client) theo đúng thứ tự và mở trình duyệt tại **http://127.0.0.1:8088**. Dừng tất cả: `scripts\stop-all.bat`.

| Việc | Windows | Linux / macOS |
|------|---------|---------------|
| Biên dịch | `scripts\build.bat` | `bash scripts/build.sh` |
| Mở toàn bộ demo | `scripts\demo-all.bat` | `bash scripts/demo-all.sh` |
| Tự kiểm thử (17 kịch bản) | `scripts\selftest.bat` | `bash scripts/selftest.sh` |
| Kiểm thử tải | `scripts\loadtest.bat` | `bash scripts/loadtest.sh` |
| Chạy từng thành phần | `scripts\1-...bat` tới `scripts\4-...bat` | `scripts/1-...sh` tới `scripts/4-...sh` |

---

## 2. Mô hình mạng mô phỏng

Toàn bộ hệ thống chạy trên **một máy** nhờ dải loopback `127.0.0.0/8`:

```
        MẠNG LAN (nội bộ)                 GATEWAY                     INTERNET
   ┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐
   │ Client 127.0.0.11    │─────►│ LAN  127.0.0.1:8080  │      │ External Server      │
   │ Client 127.0.0.12    │─────►│      127.0.0.1:8081  │─────►│ 127.0.0.3:9000 (TCP) │
   │ ...                  │      │  [ BẢNG NAT/PAT ]    │      │ 127.0.0.3:9001-9002  │
   └──────────────────────┘      │  [ FIREWALL RULES ]  │      │ (UDP)                │
   ┌──────────────────────┐      │                      │      │ "Bên thứ ba"         │
   │ Internal Service     │◄─────│ WAN  127.0.0.2       │      │ 127.0.0.4:9002 (UDP) │
   │ 127.0.0.20:7000      │      │ cổng PAT 40000-40099 │◄──── └──────────────────────┘
   └──────────────────────┘      │ port-forward :8090   │   kết nối từ ngoài vào
                                 │ web  127.0.0.1:8088  │
                                 └──────────────────────┘
```

**Bằng chứng NAT hoạt động:** External Server luôn báo lại địa chỉ nguồn mà nó *nhìn thấy*. Dù Client là `127.0.0.11`, server chỉ thấy `127.0.0.2:40000`, tức IP công cộng của Gateway.

---

## 3. Chức năng

| Nhóm | Chức năng |
|------|-----------|
| NAT/PAT | NAT động TCP/UDP; PAT nhiều phiên trên một IP công cộng; cấp cổng nguyên tử (`ConcurrentHashMap.putIfAbsent`) |
| Kiểu NAT (UDP) | Symmetric, Full-cone, Restricted-cone, Port-restricted-cone; đổi lúc đang chạy |
| Trạng thái TCP | SYN_SENT, ESTABLISHED, FIN_LAN, FIN_WAN, TIME_WAIT, RESET; hỗ trợ half-close (FIN một chiều) |
| Timeout | Thu hồi ánh xạ theo trạng thái: TCP đang kết nối 60s, TCP đang đóng 20s, UDP 30s |
| Giới hạn tài nguyên | Tối đa 20 phiên mỗi IP nội bộ; từ chối có kiểm soát khi cạn dải cổng PAT |
| Firewall | Luật ALLOW/DENY theo chiều, giao thức, IP (CIDR), cổng (dải); khớp đầu tiên thắng; đếm số lần khớp từng luật |
| An ninh | Giám sát cổng bị chặn; cảnh báo quét cổng (≥3 cổng trong 10 giây); nhật ký an ninh ra file |
| NAT tĩnh | Port Forwarding từ cổng công khai vào dịch vụ trong LAN |
| Quan sát | Console quản trị; **web dashboard** thời gian thực có nút demo |
| Kiểm thử | Bộ tự kiểm thử 17 kịch bản; kiểm thử tải đo thông lượng, độ trễ, cạn cổng |

---

## 4. Web dashboard

Mở **http://127.0.0.1:8088** khi Gateway đang chạy.

- **Bảng dịch địa chỉ:** mỗi ánh xạ là một dòng LAN → Gateway → Internet, có trạng thái TCP, số byte và thanh đếm ngược thời gian thu hồi.
- **Điều khiển demo:** chọn máy LAN (127.0.0.11/12/13 hoặc tự nhập), rồi bấm: mở phiên TCP, mở 3 phiên, thử Telnet bị chặn, gửi UDP tới 2 cổng, nhờ "bên thứ ba" gửi gói vào, quét cổng, thử Port Forwarding. Mỗi phiên có ô gửi dữ liệu, nút hỏi `whoami`, nút đóng một chiều (FIN).
- **Kiểu NAT:** 4 nút chuyển kiểu NAT, kèm giải thích.
- **Cảnh báo an ninh, luật firewall (số lần khớp), thống kê, nhật ký** tô màu theo loại.

Web chỉ lắng nghe trên `127.0.0.1`. Các nút trên web đóng vai máy LAN thật và đi qua đúng đường NAT/Firewall của Gateway.

---

## 5. Lệnh tương tác

**Client** (`scripts\4-run-client.bat 127.0.0.11`):

| Lệnh | Ý nghĩa |
|------|---------|
| `open <ip> <port>` | Mở phiên TCP ra ngoài qua Gateway |
| `multi <n> <ip> <port>` | Mở n phiên cùng lúc, mỗi phiên một cổng PAT |
| `send <id> <nội dung>` | Gửi dữ liệu (`whoami` để hỏi server thấy địa chỉ nào) |
| `half <id>` | Đóng chiều gửi (FIN), vẫn nhận dữ liệu |
| `udp <ip> <port> <nội dung>` | Gửi gói UDP (`peer` để nhờ bên thứ ba gửi vào) |
| `list` / `close <id>` / `quit` | Liệt kê / đóng phiên / thoát |

**Gateway** (console quản trị):

| Lệnh | Ý nghĩa |
|------|---------|
| `nat` | Bảng NAT/PAT, kèm số phiên theo từng IP |
| `rules` | Bộ luật firewall và số lần khớp |
| `stats` | Thống kê |
| `alerts` | Cảnh báo an ninh |
| `mode [symmetric\|full\|restricted\|port]` | Xem/đổi kiểu NAT cho UDP |
| `log [n]`, `reload`, `verbose`, `web`, `quit` | Nhật ký, nạp lại luật, bật/tắt log chi tiết, địa chỉ web, thoát |

---

## 6. Kịch bản demo

| # | Kịch bản | Thao tác (web hoặc Client) | Kết quả mong đợi |
|---|----------|----------------------------|------------------|
| 1 | NAT che giấu IP | Mở phiên TCP, hỏi `whoami` | Server thấy `127.0.0.2:40000`, không thấy `127.0.0.11` |
| 2 | PAT nhiều phiên | Mở 3 phiên cùng lúc | 3 cổng công khai khác nhau |
| 3 | Firewall chặn | Thử Telnet (cổng 23) | `403 DENY ... luật #18` |
| 4 | Kiểu NAT | Gửi UDP tới 9001 và 9002 ở chế độ Symmetric, rồi Full-cone | Symmetric: 2 cổng; Full-cone: chung 1 cổng |
| 5 | Lọc gói lạ | "Nhờ bên thứ ba gửi gói vào" ở từng kiểu NAT | Symmetric chặn hết; Full-cone cho qua hết; Restricted cho qua cùng IP |
| 6 | Half-close | Đóng chiều gửi (FIN) trên một phiên | Vẫn nhận được dòng cuối server gửi sau FIN |
| 7 | Port Forwarding | Truy cập dịch vụ nội bộ | Vào được `127.0.0.20:7000` qua `127.0.0.2:8090` |
| 8 | Quét cổng | Quét cổng Gateway | Một cảnh báo `QUET CONG` |
| 9 | Timeout | Gửi một gói UDP rồi để yên 30 giây | Dòng UDP biến mất khỏi bảng |
| 10 | Cạn cổng / giới hạn | `scripts\loadtest.bat` | Cấp đủ 100 cổng, từ chối 20 phiên dư |

---

## 7. Kiểm thử

**Tự kiểm thử** (`scripts\selftest.bat`): tự dựng môi trường riêng (cổng 18xxx/19xxx) nên chạy được cả khi demo đang mở. 17 kịch bản: NAT, PAT, firewall, đa luồng không lẫn dữ liệu, UDP, 4 kiểu NAT, Port Forwarding, cảnh báo quét cổng, giới hạn phiên/IP, cạn dải cổng, half-close, timeout, thống kê nhất quán. Kết quả lưu ở `logs/selftest-report.txt`.

**Kiểm thử tải** (`scripts\loadtest.bat [clients=50] [messages=20] [--live]`):
- Pha 1: N máy LAN (mỗi máy một IP riêng) cùng gửi dữ liệu; đo độ trễ khứ hồi và thông lượng.
- Pha 2: mở nhiều phiên hơn số cổng PAT; kiểm chứng cấp đúng số cổng và từ chối phần dư.
- `--live` bắn vào Gateway demo đang chạy để xem trực tiếp trên web (nên gõ `verbose` ở Gateway để tắt log chi tiết trước).
- Kết quả lưu ở `logs/loadtest-report.txt`.

---

## 8. Cấu trúc mã nguồn

```
src/nhom06/
├── common/    Protocol, Config, Log, Tunnel (giao thức header điều khiển)
├── gateway/
│   ├── GatewayServer      Khởi động dịch vụ, console quản trị
│   ├── NatTable, NatEntry Bảng NAT/PAT, trạng thái TCP, giới hạn phiên/IP
│   ├── NatMode            4 kiểu NAT (RFC 3489 / RFC 4787)
│   ├── NatCleaner         Thu hồi ánh xạ hết hạn theo trạng thái
│   ├── TcpNatHandler      Phiên TCP: NAT động, relay 2 chiều, half-close
│   ├── UdpNatService      PAT cho UDP theo kiểu NAT
│   ├── Firewall, FirewallRule   Bộ lọc + đếm lượt khớp + phát hiện quét cổng
│   ├── PortForwarder, InboundMonitor   NAT tĩnh, giám sát cổng bị chặn
│   └── WebDashboard, DemoClient        Web dashboard và client demo cho web
├── server/ExternalServer       Máy chủ Internet (TCP, 2 cổng UDP, "bên thứ ba")
├── internal/InternalService    Dịch vụ trong LAN (đích của Port Forwarding)
├── client/InternalClient       Máy trạm LAN (console tương tác)
└── test/   TestEnv, SelfTest, LoadTest
web/index.html       Giao diện web dashboard
config/              gateway.properties, firewall-rules.txt
docs/                Câu hỏi bảo vệ, báo cáo
```

---

## 9. Ghi chú kỹ thuật

**Vì sao cần header `CONNECT`?** NAT thật hoạt động ở tầng 3, đọc IP đích ngay trong header gói tin. Java Socket chỉ thao tác từ tầng 4 và không sửa được header IP, nên Client khai báo đích qua một dòng header ở đầu phiên. Sau đó mọi byte được chuyển tiếp nguyên trạng. Header được đọc từng byte (không dùng `BufferedReader`) để bộ đệm không "nuốt" phần dữ liệu phía sau.

**An toàn luồng.** Bảng NAT dùng `ConcurrentHashMap`; cổng được cấp bằng `putIfAbsent()` nên nguyên tử. Hàm thu hồi an toàn khi nhiều luồng cùng gọi: chỉ luồng thực sự gỡ được ánh xạ mới cập nhật thống kê. Bộ phát hiện quét cổng là `synchronized` để nhiều luồng giám sát không phát trùng cảnh báo.

**Half-close.** Khi một phía gửi FIN (`read()` trả về -1), Gateway chuyển FIN sang phía kia bằng `shutdownOutput()` nhưng vẫn giữ chiều ngược lại. Lỗi hoặc RST thì hủy cả hai chiều.

**Hạn chế của mô phỏng.** Firewall thật loại gói SYN ngay ở nhân hệ điều hành; ở đây Gateway phải `accept()` kết nối rồi mới từ chối, nên công cụ quét vẫn thấy cổng "mở" trong tích tắc. Kiểu NAT chỉ áp dụng cho UDP vì mỗi phiên TCP của Client đã là một kết nối riêng tới Gateway.

**Windows.** Nếu không dùng được `127.0.0.2`, Gateway tự lùi về `127.0.0.1` và vẫn minh hoạ PAT qua số hiệu cổng.
