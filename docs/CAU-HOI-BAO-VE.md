# Bộ câu hỏi bảo vệ có đáp án — Nhóm 06

Mỗi người nắm chắc phần của mình, và đọc qua **Phần chung** vì giảng viên hay hỏi chéo. Đáp án viết ngắn để nói thành lời; khi trả lời, chỉ vào code hoặc bấm demo minh hoạ là ăn điểm nhất.

---

## Phần chung (cả nhóm)

**1. Mô tả luồng đi của một gói tin từ Client ra Internet và quay về.**
Client (127.0.0.11) mở TCP tới Gateway (127.0.0.1:8080) và gửi dòng `NAT/1.0 CONNECT 127.0.0.3 9000`. Gateway hỏi Firewall chiều ra, cho qua thì cấp cổng công khai trong bảng NAT (ví dụ 40000), mở socket mới **bind vào 127.0.0.2:40000** rồi kết nối tới server. Server thấy nguồn là 127.0.0.2:40000. Dữ liệu trả về đi vào đúng socket đó, Gateway biết nó thuộc Client nào (vì socket gắn với ánh xạ) và chuyển ngược về Client.

**2. NAT và PAT khác nhau thế nào?**
NAT dịch địa chỉ IP: IP riêng thành IP công cộng. PAT (NAPT) dịch thêm **số cổng**, nhờ đó nhiều máy LAN dùng chung **một** IP công cộng; mỗi phiên được phân biệt bằng một cổng công khai riêng. Đồ án làm PAT: mọi Client dùng chung 127.0.0.2, mỗi phiên một cổng trong dải 40000-40099.

**3. Vì sao Client phải gửi header `CONNECT`? NAT thật đâu có vậy?**
Đúng, NAT thật ở tầng 3 đọc IP đích ngay trong header IP nên trong suốt. Java Socket chỉ làm việc từ tầng 4 trở lên, không đọc/sửa được header IP, nên Client phải khai báo đích bằng một dòng duy nhất. Sau dòng đó mọi byte đi nguyên trạng. Đây là cách các proxy như SOCKS cũng làm.

**4. Vì sao chọn Java Socket mà không dùng thư viện bắt gói như pcap?**
Môn Lập trình mạng yêu cầu Socket/ServerSocket. pcap cần quyền quản trị, driver riêng và không chạy thuần Java. Cách hiện tại chạy trên mọi máy, không cần quyền đặc biệt, dễ demo.

**5. Làm sao mô phỏng hai mạng trên một máy?**
Dùng dải loopback 127.0.0.0/8: 127.0.0.x làm LAN, 127.0.0.2 làm IP công cộng, 127.0.0.3/127.0.0.4 làm máy trên Internet. Socket có thể `bind()` vào từng địa chỉ này nên server thật sự nhìn thấy địa chỉ khác nhau.

**6. Hệ thống có những luồng nào?**
Luồng accept TCP; mỗi phiên TCP 1 luồng điều phối và 2 luồng relay (mỗi chiều một luồng); 1 luồng nhận UDP phía LAN và 1 luồng nhận chiều về cho mỗi ánh xạ UDP; 1 luồng dọn bảng NAT; mỗi cổng Port Forwarding và cổng giám sát 1 luồng; web dashboard dùng pool 6 luồng.

**7. Hạn chế của đồ án?**
(1) Không phải NAT tầng 3 thật, cần header CONNECT. (2) Firewall phải `accept()` rồi mới từ chối, nên công cụ quét thấy cổng "mở" trong tích tắc; firewall thật loại SYN ngay ở nhân. (3) Mỗi phiên TCP tốn 3 luồng; tải rất lớn nên dùng NIO (Selector). (4) Kiểu NAT chỉ áp dụng cho UDP.

**8. Nếu làm tiếp thì cải tiến gì?**
Chuyển sang Java NIO để một luồng xử lý hàng nghìn kết nối; hỗ trợ IPv6; lưu bảng NAT ra file để khôi phục khi khởi động lại; thêm xác thực cho trang web.

---

## Phần 1 — Nguyễn Duy Khang: Lõi NAT (NatTable, NatEntry, NatCleaner, GatewayServer)

**1. Bảng NAT lưu những gì, dùng cấu trúc dữ liệu nào?**
Mỗi ánh xạ (`NatEntry`) gồm giao thức, IP:cổng nội bộ, IP:cổng công khai, đích, trạng thái, số byte, thời điểm hoạt động cuối. `NatTable` giữ 3 `ConcurrentHashMap`: tra theo chiều đi (khoá nội bộ + đích), tra theo chiều về (cổng công khai, tách riêng TCP và UDP), và đếm số phiên của từng IP.

**2. Vì sao dùng `ConcurrentHashMap` mà không dùng `HashMap` + `synchronized`?**
Nhiều luồng phiên cùng tra cứu và ghi bảng NAT. `HashMap` không an toàn luồng, có thể hỏng dữ liệu. Bọc `synchronized` toàn bảng thì mọi luồng phải xếp hàng, Gateway thành nút thắt. `ConcurrentHashMap` cho phép đọc song song và khoá theo từng phần nên nhanh hơn.

**3. Làm sao đảm bảo hai luồng không bị cấp trùng một cổng công khai?**
Dùng `putIfAbsent(port, entry)`: thao tác nguyên tử, chỉ một luồng chèn được vào một cổng, luồng kia nhận lại giá trị đã có và thử cổng tiếp theo. Kiểm thử T04 (8 phiên đồng thời) và LoadTest pha 2 (120 yêu cầu cùng lúc, cấp đúng 100 cổng) chứng minh điều này.

**4. Cổng được chọn theo thuật toán nào? Hết cổng thì sao?**
Con trỏ quay vòng (round-robin) trong dải 40000-40099. Duyệt hết dải mà không còn cổng trống thì trả `503 BUSY Het cong NAT`, giống Router thật khi bảng NAT đầy (kiểm thử T14).

**5. Vì sao cần NAT timeout? Các ngưỡng là bao nhiêu?**
Nếu không thu hồi, ánh xạ của phiên đã chết chiếm cổng mãi, dải PAT cạn dần. `NatCleaner` quét mỗi 5 giây: TCP đang kết nối 60 giây, TCP đang mở/đóng 20 giây, UDP 30 giây. TCP đang đóng có ngưỡng ngắn hơn vì kết nối sắp kết thúc, giống conntrack của Linux.

**6. Có lỗi gì đã gặp trong quá trình làm và sửa thế nào?**
Ánh xạ bị thu hồi **hai lần** (NatCleaner và luồng phiên cùng gọi `release`), làm log in trùng và "Tổng thu hồi" gấp đôi "Tổng cấp phát". Sửa bằng cách chỉ luồng nào `remove()` thành công mới ghi log và tăng thống kê. Kiểm thử T17 kiểm tra `cấp phát = thu hồi + đang mở`.

**7. Giới hạn số phiên mỗi IP để làm gì? Cài đặt thế nào?**
Chống một máy (nhiễm mã độc chẳng hạn) mở hàng nghìn kết nối chiếm hết cổng NAT của cả mạng. Mỗi IP có một bộ đếm `AtomicInteger`; tăng trước khi cấp, vượt 20 thì giảm lại và từ chối, thu hồi thì giảm (kiểm thử T13).

**8. Gateway xử lý thế nào nếu không bind được 127.0.0.2 trên Windows?**
Lúc khởi động thử bind; thất bại thì ghi cảnh báo và tự dùng IP LAN (127.0.0.1). PAT vẫn minh hoạ được qua số hiệu cổng.

---

## Phần 2 — Nguyễn Hữu Đạt: Chuyển tiếp TCP/UDP, đa luồng (TcpNatHandler, UdpNatService, Tunnel)

**1. Gateway chuyển dữ liệu hai chiều thế nào?**
Mỗi phiên có 2 luồng `Relay`: một luồng đọc từ Client ghi sang server, một luồng đọc từ server ghi về Client. Mỗi luồng là một vòng `read()` / `write()` với bộ đệm 8 KB, đồng thời cộng số byte và cập nhật thời điểm hoạt động.

**2. Vì sao mỗi chiều một luồng?**
`read()` của Socket là thao tác chặn. Nếu một luồng lo cả hai chiều, khi nó đang chờ dữ liệu từ Client thì dữ liệu từ server bị kẹt. Hai luồng độc lập giúp hai chiều chạy song song.

**3. Đọc header CONNECT sao cho không làm hỏng dữ liệu phía sau?**
Đọc **từng byte** tới ký tự xuống dòng (`Tunnel.readLine`). Nếu dùng `BufferedReader`, nó đọc trước cả khối 8 KB vào bộ đệm riêng, "nuốt" luôn phần dữ liệu sau header, luồng relay sẽ mất dữ liệu.

**4. Half-close là gì và Gateway xử lý ra sao?**
TCP cho phép một phía ngừng gửi (gửi FIN) nhưng vẫn nhận. Khi `read()` trả về -1 tức phía đó đã gửi FIN, Gateway chuyển FIN sang phía kia bằng `shutdownOutput()` nhưng **không đóng socket**, chiều ngược lại vẫn chạy. Demo: nút "Đóng chiều gửi (FIN)", server vẫn gửi được dòng cuối (kiểm thử T15). Phiên bản đầu đóng cả hai chiều, đã sửa để đúng chuẩn RFC 793.

**5. FIN khác RST thế nào trong code?**
FIN: `read()` trả -1, kết thúc êm, chuyển trạng thái FIN_LAN hoặc FIN_WAN. RST hoặc lỗi: `read()` ném `IOException`, Gateway đánh dấu RESET và đóng cả hai socket ngay.

**6. UDP không có kết nối, Gateway biết gói trả về thuộc Client nào bằng cách nào?**
Mỗi ánh xạ UDP có một `DatagramSocket` riêng bind vào cổng công khai. Gói trả về tới cổng nào thì thuộc ánh xạ đó, Gateway thêm header `FROM ip port` rồi gửi về đúng IP:cổng của Client.

**7. Khi nào phiên UDP kết thúc?**
UDP không có FIN nên dựa hoàn toàn vào thời gian im lặng: 30 giây không có gói thì `NatCleaner` thu hồi (kiểm thử T16 dùng 2 giây).

**8. Nếu kết nối tới server thất bại thì sao?**
Phân biệt hai loại: server không phản hồi (`ConnectException`, timeout) thì thu hồi cổng và báo lỗi ngay; còn lỗi do cổng công khai đang bị hệ điều hành giữ (ví dụ TIME_WAIT) thì thử cổng khác, tối đa 5 lần.

---

## Phần 3 — Trần Xuân Dưỡng: Firewall, Port Forwarding, an ninh (Firewall, FirewallRule, PortForwarder, InboundMonitor)

**1. Firewall quyết định cho qua hay chặn thế nào?**
Duyệt luật từ trên xuống, **luật khớp đầu tiên thắng**, giống ACL của Cisco hay iptables. Không luật nào khớp thì dùng chính sách mặc định: ra cho phép, vào chặn.

**2. Một luật gồm những gì? Hỗ trợ định dạng gì?**
`ACTION DIRECTION PROTO SRC_IP SRC_PORT DST_IP DST_PORT`. IP hỗ trợ `*`, địa chỉ cụ thể, CIDR (`127.0.0.0/8`); cổng hỗ trợ `*`, số cụ thể, dải (`137-139`).

**3. So khớp CIDR làm thế nào?**
Đổi IP thành số 32 bit, tạo mặt nạ từ số bit mạng (`0xFFFFFFFF << (32 - n)`), rồi so `(ip & mask) == (mạng & mask)`.

**4. Vì sao thứ tự luật quan trọng? Cho ví dụ.**
Nếu đặt `ALLOW OUT TCP 127.0.0.0/8 * * *` lên trên `DENY OUT TCP * * * 23` thì Telnet sẽ lọt qua vì luật cho phép khớp trước. Luật cụ thể phải đặt trên luật chung.

**5. "Stateful" nghĩa là gì trong đồ án?**
Gói trả về trên một phiên đã có trong bảng NAT được cho qua mà không cần luật IN, vì Gateway nhớ trạng thái kết nối. Với UDP, gói về còn bị lọc theo kiểu NAT: chỉ nhận từ nguồn mà Client đã gửi tới (trừ Full-cone).

**6. Phát hiện quét cổng thế nào?**
Mỗi lần kết nối vào bị chặn, ghi lại IP nguồn và cổng. Nếu một IP bị chặn ở **từ 3 cổng khác nhau trong 10 giây** thì phát cảnh báo. Có chống lặp: cùng IP chỉ cảnh báo lại sau 10 giây.

**7. Từng có lỗi cảnh báo bị in 3 lần, nguyên nhân?**
Ba cổng giám sát chạy ba luồng. Cả ba cùng kiểm tra "chưa cảnh báo IP này" trước khi bất kỳ luồng nào kịp ghi lại, nên cả ba cùng phát (lỗi check-then-act). Sửa bằng `synchronized` cho hàm ghi nhận, kiểm thử T12 kiểm tra đúng 1 cảnh báo.

**8. Port Forwarding khác NAT động thế nào?**
NAT động: bên trong chủ động ra ngoài, ánh xạ tạo tự động, có timeout. Port Forwarding (NAT tĩnh, DNAT): bên ngoài chủ động vào; ánh xạ cố định do quản trị cấu hình (`8090>127.0.0.20:7000`), không hết hạn, vẫn phải qua luật IN.

**9. Đếm số lần khớp luật để làm gì?**
Biết luật nào đang thực sự hoạt động, luật nào thừa không bao giờ khớp. Quản trị firewall thật cũng dùng bộ đếm này (`iptables -L -v`).

---

## Phần 4 — Trần Huy Hoàng: Client, Server, web dashboard, kiểm thử (InternalClient, ExternalServer, WebDashboard, SelfTest, LoadTest)

**1. Làm sao chứng minh NAT đã hoạt động?**
External Server luôn trả lời "tôi nhìn thấy bạn tại ...". Client 127.0.0.11 hỏi `whoami`, server trả `127.0.0.2:40000`: IP riêng không bao giờ lộ ra ngoài (kiểm thử T01).

**2. Client gắn IP riêng (127.0.0.11) bằng cách nào?**
`socket.bind(new InetSocketAddress("127.0.0.11", 0))` trước khi `connect()`. Cổng 0 để hệ điều hành tự chọn cổng nguồn.

**3. Bốn kiểu NAT khác nhau thế nào, demo ra sao?**
Hai câu hỏi: ánh xạ có phụ thuộc đích không, và lọc gói về theo gì. Symmetric: mỗi đích một cổng, chỉ nhận từ đúng IP:cổng đã gửi. Full-cone: chung cổng, nhận từ mọi nguồn. Restricted-cone: chung cổng, nhận từ IP đã gửi. Port-restricted: chung cổng, nhận từ đúng IP:cổng đã gửi. Demo: gửi UDP tới 2 cổng để xem ánh xạ, rồi nhờ "bên thứ ba" (127.0.0.3:9002 cùng IP, 127.0.0.4:9002 khác IP) gửi gói vào để xem bộ lọc (kiểm thử T06-T10).

**4. Kiểu NAT ảnh hưởng gì trong thực tế?**
Quyết định ứng dụng P2P, gọi video, game có kết nối trực tiếp được không. Symmetric khó "đục lỗ" (hole punching) nhất vì cổng thay đổi theo đích; Full-cone dễ nhất nhưng kém an toàn.

**5. Web dashboard hoạt động thế nào?**
Gateway mở thêm HTTP server (`com.sun.net.httpserver`, có sẵn trong JDK) tại 127.0.0.1:8088. Trang web gọi `/api/state` mỗi giây để lấy JSON trạng thái và vẽ lại. Các nút gọi `/api/action`; lớp `DemoClient` bind đúng IP LAN được chọn và đi qua Gateway như Client thật, nên mọi thao tác đi đúng đường NAT/Firewall.

**6. Bộ tự kiểm thử kiểm tra những gì?**
17 kịch bản: NAT, PAT, firewall chặn, 8 phiên đồng thời không lẫn dữ liệu, UDP, 4 kiểu NAT, Port Forwarding, cảnh báo quét cổng, giới hạn phiên/IP, cạn dải cổng, half-close, timeout, thống kê nhất quán. Nó tự dựng môi trường riêng nên chạy bằng một lệnh, kết quả 17/17 PASS.

**7. Kiểm thử tải đo gì và kết quả ra sao?**
Pha 1: 50 máy LAN cùng gửi 20 thông điệp, đo thông lượng và độ trễ khứ hồi; 1000/1000 thông điệp đúng người nhận. Pha 2: 120 yêu cầu cùng lúc với dải 100 cổng, cấp đúng 100 và từ chối đúng 20. Số liệu cụ thể trong báo cáo và `logs/loadtest-report.txt`; chạy lại trên máy demo sẽ ra số khác tùy cấu hình máy.

**8. Vì sao khi kiểm thử phải đóng phiên bằng "bye" chứ không đóng socket ngay?**
Bên nào đóng trước sẽ rơi vào TIME_WAIT. Nếu Gateway đóng trước, cổng công khai bị giữ vài chục giây và kết nối lại cùng đích có thể lỗi. Gửi "bye" để server đóng trước, TIME_WAIT nằm ở phía server.
