# Báo cáo đồ án — Sentinell: Nhắn tin bảo mật đầu cuối P2P đa nền tảng

Môn: **An toàn và Bảo mật thông tin**
Tài liệu tham khảo chính:
- *Bài giảng An toàn và Bảo mật thông tin* — Lê Việt Nam, ĐH Hồng Đức (viết tắt **[BG]**).
- *Giáo trình Lý thuyết Mật mã* — Trịnh Viết Cường (chủ biên) và cộng sự (viết tắt **[GT]**).

---

## 1. Bài toán, tiêu chí và mô hình đe dọa

Xây dựng ứng dụng cho **hai thiết bị nối trực tiếp trên mạng LAN** để nhắn tin bảo mật theo mô
hình **ngang hàng** — mỗi thiết bị là một node độc lập, không có máy chủ trung gian đọc được nội
dung. Năm tiêu chí đề bài:

| # | Tiêu chí | Đáp ứng |
|---|---|---|
| 1 | Lưu trữ cục bộ (PC/mobile) | Khóa trong tệp (bí mật bọc DPAPI/Keychain); tin nhắn SQLite **mã hóa at-rest** |
| 2 | Quản lý khóa (tạo, đổi) | Tạo tự động, xoay khóa, sao lưu/phục hồi, ghim khóa liên hệ |
| 3 | Nhắn tin mã hóa | ECDHE + ECDSA + HKDF + AES-256-GCM + ratchet |
| 4 | Tìm kiếm trên LAN | mDNS/DNS-SD (`_sentinell._tcp`) |
| 5 | Trao đổi khóa qua QR | Quét QR khóa công khai (out-of-band) để ghim, chống mạo danh |

Mô hình đe dọa: mạng LAN bị coi là **không tin cậy** — kẻ tấn công có thể nghe lén, chèn, sửa,
tráo khóa ([BG 4.5]). Đây đúng giả định của mã hóa đầu cuối ([BG 4.10]).

## 2. Kiến trúc: một lõi giao thức — nhiều nền tảng

```
core/protocol.js  (JavaScript, thư viện @noble đã kiểm định)
   │
   ├── desktop/  Electron (Windows): Node.js làm node — mDNS, WebSocket /peer, SQLite, safeStorage
   │             giao diện web/ trong cửa sổ  →  Sentinell.exe
   ├── web/join  Điện thoại qua trình duyệt (không cài app): cùng lõi chạy trong trình duyệt,
   │             bắt tay thẳng với /peer của PC — PC KHÔNG giữ khóa của điện thoại
   ├── mobile/   React Native (Expo) — bản build Android là node ĐẦY ĐỦ: nghe kết nối (máy chủ
   │             WebSocket tự viết theo RFC 6455), mDNS, khóa bọc bằng mật khẩu (scrypt native),
   │             lịch sử SQLite mã hóa at-rest; iPhone vẫn chạy được qua Expo Go (chỉ gọi đi)
   └── reference/python/  Bản tham chiếu Python (cryptography, zeroconf) — vẫn là peer hợp lệ
```

Cùng một `core/protocol.js` chạy trên bốn môi trường khác nhau (Node.js/Electron, trình duyệt,
Hermes/React Native, và đối chiếu với Python) là minh chứng cho luận điểm ở mục 2.3: giao thức
được đặc tả đủ chặt để không phụ thuộc cài đặt hay ngôn ngữ.

Ba quyết định thiết kế quan trọng:

1. **Node là đầu cuối thật.** Mật mã chạy trong tiến trình của từng thiết bị (Electron/Node.js
   trên PC, trình duyệt trên điện thoại, Python ở bản tham chiếu). Dữ liệu rời thiết bị đã là
   bản mã; giữa hai node không có ai ở giữa.
2. **Giao diện PC mở ở `localhost`** (secure context) → camera quét QR chạy được. Trang mở qua
   `http://<IP>` của máy khác là *insecure context*: trình duyệt chặn camera và WebCrypto —
   đây là lý do kỹ thuật buộc chọn mô hình node thay vì "một host + trình duyệt khách".
3. **Đặc tả giao thức độc lập ngôn ngữ.** Cùng một khuôn gói tin, transcript, HKDF, nonce,
   AAD và định dạng chữ ký (DER) được cài đặt bằng JavaScript và Python; bộ test vector chéo
   (`scripts/`) chứng minh hai cài đặt cho **cùng kết quả** và bắt tay/giải mã được của nhau.

## 3. Giao thức mật mã

1. **Danh tính**: cặp khóa ECDSA P-256 sinh lần đầu, lưu cục bộ ([BG ch.3] — chữ ký số thay
   vai trò chứng thư giữa hai cá nhân không có CA).
2. **Bắt tay có xác thực** (initiator I / responder R):
   - Mỗi bên gửi `{id_pub, eph_pub, nonce}`; `eph` là khóa ECDH **tạm thời** → *forward
     secrecy* ([BG 4.4]).
   - Transcript chuẩn tắc `T = tag ‖ I.id ‖ I.eph ‖ I.nonce ‖ R.id ‖ R.eph ‖ R.nonce`; mỗi bên
     **ký** `SHA-256(T)` bằng ECDSA (chữ ký DER), bên kia **xác minh** ([BG 4.5] chống MITM).
   - Nếu khóa danh tính của peer đã được **ghim qua QR**, còn đối chiếu khóa: khác → hủy
     (phát hiện mạo danh). Khóa lạ → tin-khi-dùng-lần-đầu (TOFU), cảnh báo nên quét QR.
3. **Dẫn xuất khóa**: `x = ECDH(eph)` (tọa độ x); `HKDF-SHA256(x, salt = nonceI‖nonceR,
   info = "sentinell-root-v2", 64 byte)` → hai chain key theo chiều ([BG 4.1.3]).
4. **Safety number**: `SHA-256(hai khóa danh tính)` → 60 chữ số để đối chiếu ([BG 4.5]).
5. **Mỗi tin nhắn** ([BG 4.10]): `mk = HKDF(ck,"sentinell-msg")`, `ck ← HKDF(ck,"sentinell-chain")`;
   `AES-256-GCM(mk, nonce = [dir‖0…‖seq], AAD = {seq,dir,type})` ([GT 2.6.5] — mã hóa kèm xác
   thực); khóa `mk` xóa ngay sau dùng. GCM tự phát hiện mọi sửa đổi ⇒ toàn vẹn.
6. **File/ảnh** ([BG 4.1] bài toán "tệp lớn"): chia khối 256 KB, mỗi khối mã hóa như một tin
   (một bước ratchet, một khóa riêng); kèm SHA-256 toàn tệp để đối chiếu toàn vẹn sau khi ghép.
   Khối tệp đi bằng **khung nhị phân** `"SNT1" ‖ dir ‖ len(mtype) ‖ seq ‖ mtype ‖ GCM(meta‖bytes)`
   thay vì nhét vào JSON: đường JSON buộc phải base64 nội dung (+33%) rồi in bản mã ra hex
   (+100%) ⇒ **2,67 byte trên dây cho mỗi byte tệp**; khung nhị phân đưa tỉ lệ đó về **1,00**
   (đo được bằng `npm run test:file`). Phần đầu khung chỉ để lộ đúng những trường mà gói JSON
   cũng để lộ (`seq`, `dir`, `mtype` — cần để dựng AAD); **tên tệp nằm trong vùng đã mã hóa**.
   AAD thêm `bin:1` để không thể tráo khung nhị phân thành gói JSON cùng `seq`/`mtype`.

## 4. Bốn tính chất an toàn

| Tính chất | Cơ chế |
|---|---|
| Bí mật | AES-256-GCM; mạng chỉ thấy bản mã |
| Toàn vẹn | Thẻ xác thực GCM; sửa 1 bit → từ chối giải mã |
| Xác thực | Chữ ký ECDSA trên transcript + ghim khóa qua QR + safety number |
| Chống chối bỏ | Chữ ký ECDSA gắn danh tính người gửi vào transcript |
| Forward secrecy | Khóa ephemeral mỗi phiên + ratchet mỗi tin nhắn |

## 5. Tìm kiếm trên LAN (tiêu chí 4)

mDNS/DNS-SD: node quảng bá dịch vụ `_sentinell._tcp.local.` (TXT: id, tên, vân tay, khóa công
khai) và duyệt để phát hiện node khác. Cài đặt bằng `bonjour-service` (Node.js), `zeroconf`
(Python) và NsdManager của Android (qua `react-native-zeroconf`) — cùng loại dịch vụ, cùng khóa
TXT nên **nhìn thấy nhau**. Mạng chặn multicast → nhập IP:cổng thủ công.

TXT mDNS là thông tin **tự khai, không có chữ ký**: ai cũng quảng bá được tên và khóa bất kỳ. Vì
thế khóa trong TXT chỉ để hiển thị; app chỉ coi một máy trong danh sách LAN là "đã ghim" khi khóa
đó **trùng một khóa đã ghim qua QR**, còn lại kết nối như máy lạ (phải duyệt, đối chiếu safety
number). Tìm thấy ≠ tin được — việc xác thực vẫn thuộc về chữ ký trong bắt tay (mục 3).

### 5.1. Điện thoại nghe kết nối — tự viết máy chủ WebSocket

React Native có WebSocket để **gọi đi** nhưng không có cách nào để **nghe**. Thư viện
`react-native-tcp-socket` chỉ cho TCP trần, nên phần giao thức WebSocket (RFC 6455) được cài
đặt tay (`mobile/src/wsproto.js`): bắt tay HTTP Upgrade với `Sec-WebSocket-Accept =
Base64(SHA-1(key ‖ GUID))`, khung độ dài 7/16/64-bit, bắt buộc mặt nạ từ client, ghép tin chia
khung, ping/pong, đóng tử tế. Hai điểm an toàn cài đặt: **kiểm độ dài khung trước khi gom byte**
(khai 2 GB → đóng ngay với mã 1009, không cấp phát gì — cùng họ lỗi DoS đã vá ở `file-meta`), và
**nhịp tim** phát hiện đối phương chết để điện thoại không kẹt "đang bận". Tính đúng đắn được
kiểm bằng chính thư viện `ws` của desktop làm client (mục 8).

SHA-1 ở đây KHÔNG dùng cho an toàn: nó chỉ là hằng số bắt tay do RFC 6455 quy định để chứng tỏ
máy chủ hiểu WebSocket. Toàn bộ bí mật và toàn vẹn nằm ở tầng Sentinell phía trên (ECDH, ECDSA,
AES-256-GCM).

## 6. Trao đổi khóa qua QR (tiêu chí 5) — chống mạo danh

Giữa hai cá nhân không có CA, trao khóa qua chính kênh mạng có thể bị tráo ([BG 4.5]). Sentinell
trao khóa **out-of-band qua QR**:
- **PC ↔ PC**: mỗi node hiện QR chứa khóa công khai; máy kia quét bằng webcam (UI ở `localhost`
  nên camera chạy) và ghim vào danh bạ; khi bắt tay, khóa peer đối chiếu với khóa đã ghim.
- **PC ↔ điện thoại**: PC hiện QR `http://<ip>:<port>/join#k=<khóa PC>`. Điện thoại quét bằng
  **camera hệ thống** (không cần secure context của web), mở trang `/join`, đọc khóa PC ở phần
  `#` (không gửi lên mạng) và ghim → bắt tay với `expectPub` = khóa PC. Điện thoại hiện QR khóa
  của mình để PC quét ghim ngược, hoặc hai bên đối chiếu safety number.

### 6.1. Ghép đôi hai chiều bằng một lần quét

Bản đầu chỉ ghim **một chiều**: bên quét học được khóa của bên hiện QR, còn bên hiện QR
không học được gì — trái với trực giác của một ứng dụng nhắn tin (muốn nhắn lại phải quét ngược).

Giải pháp: QR mang thêm **mã ghép đôi dùng một lần** (dạng 3 từ dễ đọc). Bên quét gửi kèm
`pair_proof = HMAC-SHA256(mã, SHA-256(transcript))` trong gói chữ ký handshake. Bên hiện QR
kiểm HMAC bằng mã của chính mình; khớp ⇒ khóa của bên quét cũng được xác thực **ngoài kênh
mạng** ⇒ tự ghim ⇒ **ghim hai chiều chỉ với một lần quét**.

Vì sao gửi HMAC chứ không gửi thẳng mã: mã đi qua QR (ngoài kênh), còn HMAC **gắn chặt với
transcript** của đúng phiên đó — kẻ nghe lén không suy ra được mã và **không tái sử dụng
được bằng chứng cho phiên khác** (đã kiểm chứng bằng thử nghiệm phát lại). Mã đổi ngay sau
khi ghép thành công (dùng một lần).

Mỗi bên còn khai báo **cổng đang lắng nghe** trong handshake, nên danh bạ lưu đủ địa chỉ để
bên nào cũng chủ động mở lại cuộc trò chuyện.

### 6.2. Kiểm soát kết nối đến — mã hóa không thay được quyền quyết định

Mã hóa chống nghe lén; nó **không** trả lời câu hỏi "có nên nói chuyện với người này không".
Bản đầu, bất kỳ ai chung mạng LAN cũng tự mở được phiên vì handshake luôn thành công — chữ ký
ECDSA hợp lệ chỉ chứng minh *ai đó* giữ khóa, chứ không chứng minh *khóa của ai* [BG 4.5].

Vì vậy phía nhận có hai lớp:

| Tình huống | Hành vi |
|---|---|
| Khóa đã ghim (đã quét QR) | vào thẳng, huy hiệu *đã xác minh ✓* |
| Khóa lạ, chế độ thường | **hỏi người dùng** Chấp nhận / Từ chối, tự từ chối sau 60s |
| Khóa lạ, **chế độ chặt** | từ chối ngay, kèm lý do |

Bên gọi nhận khung `{type:"pending"}` ngay khi bên kia bắt đầu hỏi, nên hiển thị đúng
"⏳ chờ máy tính duyệt" thay vì treo im lặng; bị từ chối thì nhận `{type:"rejected"}` kèm lý do.

Chi tiết cài đặt đáng lưu ý: chữ ký handshake của bên gọi thường **đến trước** lúc người dùng
kịp bấm duyệt. Gói đó được giữ lại (`_deferredSig`) và xử lý lại sau khi chấp nhận, nếu không
phiên sẽ vỡ vì `session.peer` còn rỗng.

## 7. Lưu trữ cục bộ và quản lý khóa (tiêu chí 1 & 2)

Trên **PC (Electron)**:
- **Khóa**: `identity.json`; khóa bí mật và khóa lưu trữ được bọc thêm bằng `safeStorage`
  (Windows DPAPI / macOS Keychain) trước khi ghi đĩa (`protected: true`).
- **Tin nhắn**: SQLite `messages.db` (sql.js), mỗi bản ghi mã hóa AES-256-GCM với khóa lưu trữ
  cục bộ → mở tệp chỉ thấy bản mã.

Trên **điện thoại (Expo/React Native)**:
- **Khóa**: `expo-secure-store` → Keychain (iOS) / Keystore (Android) — kho khóa do hệ điều
  hành bảo vệ, đúng nguyên tắc "khóa giá trị cao nên nằm trong kho khóa chuyên dụng" [BG 4.7].
- **Tin nhắn**: `expo-sqlite`, nội dung bọc bằng `sealLocal` (AES-256-GCM) của lõi chung.
- Ảnh nhận được **không** lưu base64 vào kho để tránh phình dữ liệu; chỉ lưu siêu dữ liệu.

Chung cho cả hai: **xoay khóa** giữ nguyên khóa lưu trữ nên lịch sử cũ vẫn đọc được, khóa cũ
được ghi vào danh sách `archived`; bản PC có thêm **sao lưu/phục hồi** danh tính dạng JSON.

**Tài khoản cục bộ — dẫn khóa từ mật khẩu.** `safeStorage` (DPAPI) gắn với *tài khoản Windows*,
nên ai đăng nhập được vào máy cũng mở được Sentinell. Đặt mật khẩu sẽ đổi hẳn gốc tin cậy:

```
mật khẩu --scrypt(N = 2¹⁷, r = 8, p = 1, salt 16 byte ngẫu nhiên)--> KEK 32 byte
identity.json chỉ còn:  AES-256-GCM(KEK, {priv, storage_key})
```

scrypt được chọn thay vì băm thẳng vì nó **cố ý tốn cả thời gian lẫn bộ nhớ** (≈128 MB mỗi lần
thử — mức khuyến nghị của OWASP), khiến việc dò hàng loạt bằng GPU/ASIC đắt lên nhiều bậc — đúng vai trò của một hàm dẫn
xuất khóa từ mật khẩu [GT 4.1]. **Thẻ xác thực của GCM đóng luôn vai trò kiểm mật khẩu**: sai
mật khẩu thì phép giải mã thất bại, nên không cần lưu thêm "giá trị kiểm tra" — thứ chỉ giúp
kẻ dò thử loại trừ nhanh hơn. Vì `storage_key` nằm trong gói này, mật khẩu cũng là thứ chặn
đường vào kho tin nhắn.

Khi chưa mở khóa, node **không quảng bá mDNS**, `/api/info` chỉ trả `{locked:true}`, và mọi
kết nối `/peer` bị từ chối kèm lý do — máy đang khóa thì coi như không có mặt trên mạng.

**Trên app Android** cơ chế y hệt (không có mật khẩu thì khóa chỉ được Keystore của Android bảo
vệ — ai mở được máy là mở được app). Đang khóa thì điện thoại **không nghe cổng nào, không quảng
bá mDNS**; rời app quá 5 phút thì tự khóa lại. Một bài học cài đặt đáng ghi: scrypt viết bằng
JavaScript thuần chạy trên Hermes (máy ảo JS của React Native, **không có JIT**) mất 17,7 giây
ngay ở mức thấp N = 2¹⁴ — đủ để người dùng bỏ đặt mật khẩu, hoặc để lập trình viên lén hạ tham số
xuống mức vô dụng. Chuyển sang scrypt native (OpenSSL) thì cùng mức đó còn 153 ms, và app **đo
thật trên chính máy** rồi chọn N lớn nhất trong ~1,5 s — máy ảo chọn được 2¹⁷ (626 ms), bằng
desktop. Tham số được lưu theo từng tài khoản nên máy yếu hơn vẫn mở được tài khoản của mình.

**Sao lưu luôn được mã hóa.** Tệp sao lưu/chuyển máy (`.sen`) dùng đúng cơ chế trên: khóa bí
mật nằm trong gói scrypt+GCM, nên tệp rơi vào tay người khác vẫn phải có mật khẩu mới mở
được. Máy chưa đặt mật khẩu cho app vẫn sao lưu được — chỉ cần đặt một mật khẩu riêng cho tệp.
Đây là chỗ dễ hỏng nhất trong thực tế: bảo vệ kho rất kỹ rồi mà để một nút "xuất khóa" không
mã hóa thì toàn bộ công sức phía trước thành vô nghĩa.

**Xóa vĩnh viễn và siêu dữ liệu.** Xóa cuộc trò chuyện chỉ đánh dấu `deleted_at` (vào mục
"Đã xóa", và mọi truy vấn kể cả tìm kiếm đều bỏ qua). Chỉ khi người dùng chọn *xóa vĩnh viễn*
mới thật sự `DELETE` — kèm `VACUUM`, vì `DELETE` của SQLite chỉ đánh dấu trang là trống chứ
không xóa bytes: bản mã, mốc thời gian và **khóa công khai của người kia** vẫn nằm lại trong
tệp. Nội dung thì đã mã hóa, nhưng *đã nói chuyện với ai, lúc nào, bao nhiêu tin* cũng là
thông tin cần giấu — bảo vệ nội dung mà để hở siêu dữ liệu là bảo vệ nửa vời.

**Cái giá của việc mã hóa kho — nhìn qua chức năng tìm kiếm.** Tìm trong tin nhắn *không thể*
dùng `LIKE` của SQL: cột `body_ct` là bản mã AES-256-GCM, trong tệp `.db` chỉ là bytes ngẫu
nhiên, và chính vì thế kẻ lấy được tệp đó cũng không dò ra được chữ nào. Muốn tìm thì phải
giải mã từng dòng bằng khóa lưu trữ rồi so trong bộ nhớ — đây là ví dụ cụ thể cho nhận định
"mã hóa dữ liệu lúc nghỉ đánh đổi khả năng truy vấn lấy tính bí mật". Bộ kiểm thử
`npm run test:search` chứng minh bằng cách đọc thẳng tệp `.db` và xác nhận không có chuỗi nào
ở dạng đọc được. Để bù phần hiệu năng, việc quét đi từ bản ghi mới nhất về cũ và dừng khi đủ
số kết quả cần hiển thị.

## 7b. Mô hình đe dọa — chặn được gì, KHÔNG chặn được gì

Một hệ thống bảo mật chỉ đáng tin khi nó nói rõ được giới hạn của chính nó. Bảng dưới là
ranh giới thật của Sentinell.

| Kiểu tấn công | Kết quả | Nhờ đâu |
|---|---|---|
| Nghe lén thụ động (Wireshark, bắt sóng WiFi) | **Chặn** | AES-256-GCM, khóa chưa bao giờ đi qua dây |
| Sửa nội dung gói tin trên đường | **Chặn** | thẻ xác thực GCM — đổi 1 byte là bên nhận từ chối |
| Phát lại gói cũ | **Chặn** | `seq` lệch là cảnh báo |
| Kẻ đứng giữa **tráo khóa** lúc bắt tay | **Chặn** | ký transcript bằng ECDSA + ghim khóa qua QR + safety number |
| Về sau trộm được khóa danh tính, đem giải mã đống gói đã bắt | **Chặn** | ECDH **tạm thời** ⇒ forward secrecy |
| Lấy được tệp `messages.db` | **Chặn** | mã hóa at-rest; có mật khẩu thì khóa kho cũng nằm trong gói scrypt |
| Máy khác trong LAN gọi vào cổng điều khiển | **Chặn** *(từ 3.10.1)* | `/ui` và `/file/*` chỉ nhận loopback |
| Thiết bị lạ xin kết nối | **Chặn** | phải người dùng bấm duyệt; chế độ chặt thì từ chối thẳng |
| **Sửa mã JS lúc `/join` tải về** | **KHÔNG chặn được bằng mật mã** | xem bên dưới |
| Giữ được máy đã mở khóa | Không chặn | ngoài phạm vi — đây là việc của khóa màn hình hệ điều hành |
| Siêu dữ liệu (ai–với–ai, lúc nào, dài bao nhiêu) | Không giấu | mDNS và gói bắt tay đi bản rõ |

**Về dòng in đậm.** Trang `/join` tải mã JavaScript qua HTTP. Kẻ đứng trên đường sửa được
đoạn mã đó, và khi ấy nó đọc bản rõ **trước khi** mã hóa xảy ra — mã hóa vẫn hoàn hảo, chỉ
là nó đang mã hóa cho kẻ tấn công. QR và safety number **không cứu được** chỗ này, vì mã đã
bị sửa thì cứ việc hiện lên đúng dãy số người dùng mong đợi.

Đây **không phải thiếu sót riêng của đồ án**: đó là giới hạn đã biết của mọi hệ thống mật mã
chạy trong trình duyệt được tải qua mạng — Cloudflare gọi là bài toán "con gà–quả trứng",
và W3C đang làm dở đặc tả **WAICT** cho đúng vấn đề này, chưa trình duyệt nào có. HTTPS
chứng chỉ tự ký **không giải quyết được**: người dùng bấm qua cảnh báo đỏ y hệt với chứng chỉ
của kẻ tấn công, mà Let's Encrypt thì không cấp chứng chỉ cho IP nội bộ.

Vì không vá được bằng mật mã, Sentinell vá bằng **kiến trúc**:

1. **Bản đầy đủ là ứng dụng cài đặt** (desktop, Android) — mã nằm sẵn trên máy, không tải
   qua mạng lần nào, nên hoàn toàn không dính.
   *Trường hợp buộc phải dùng chế độ web* (điện thoại iOS — chưa có bản cài riêng): dựng
   đường trực tiếp bằng **điểm phát sóng theo chiều nào cũng được**. Máy tính phát thì địa
   chỉ rơi vào `192.168.137.x`; máy tính không phát được thì cho **điện thoại phát** và máy
   tính nối vào — iPhone cố định `172.20.10.x/28`, Android `192.168.43.x`. Máy tính **không
   có card WiFi** (chỉ cắm dây, đang ở mạng trường/công ty) thì **cắm cáp USB**: iOS dùng
   chung dải `172.20.10.x/28` cho cả WiFi, USB lẫn Bluetooth, nên vẫn là đường trực tiếp —
   và là đường an toàn nhất vì không có sóng nào để nghe. Cả ba dải đều được app nhận diện,
   gắn nhãn "nối trực tiếp" và **tự ưu tiên** khi dựng mã QR.
2. **Chế độ web khóa theo card mạng** — chỉ mạng con đang được chia sẻ mới tải được mã.
   Bật điểm phát sóng là kẻ ở WiFi gốc không với tới được.
3. **Nhận diện loại mạng** — cửa sổ QR nói rõ đường đang dùng là nối trực tiếp, mạng riêng
   hay mạng công cộng, kèm hướng dẫn chuyển sang điểm phát sóng.
4. **Rà dấu vết kẻ đứng giữa** — không kiểm được *mã có bị sửa không* (phải hỏi chính đoạn
   mã đã bị sửa), nhưng kiểm được *có ai đang chen vào đường không*. Giả mạo ARP — cách
   chen vào phổ biến nhất trong LAN — để lại dấu vết trong bảng láng giềng của chính máy
   này: một MAC đứng tên nhiều IP, hoặc MAC của một IP đổi giữa chừng. Cộng thêm việc đếm
   xem *mấy thiết bị đã tải mã web* trong lượt ghép đôi. Cả hai chạy lại mỗi 4 giây trong
   lúc cửa sổ QR mở, nên cảnh báo đến trước tin nhắn đầu tiên.
   Đây là **phát hiện**, không phải **ngăn chặn**, và chỉ bắt được kiểu phổ biến nhất —
   giao diện nói rõ điều đó thay vì hiện một dấu "✅ an toàn" gây yên tâm sai chỗ.
5. **Bẫy dây trong mã web** — trang `/join` tự rà xem các hàm nền tảng của trình duyệt
   (`WebSocket.send`, `fetch`, `crypto.getRandomValues`…) có còn là `[native code]` không,
   và trên trang có thẻ `<script>` lạ nào không. Kẻ tấn công lười dùng đòn tổng quát là ghi
   đè các hàm đó để chép bản rõ trước khi mã hóa; đòn ấy để lại dấu. Báo động đi qua **đường
   đã mã hóa** (bỏ gói thì `seq` lệch, sửa gói thì GCM từ chối), và **phản ứng nằm ở máy
   tính**: ngắt phiên ngay — vì phản ứng chạy trong đoạn mã đã bị chiếm thì vô nghĩa.

   Về nguyên tắc, bẫy này **không thể** là bảo vệ: tệp JS được phục vụ công khai nên kẻ tấn
   công đọc được cả đoạn bẫy, và **thứ gì mã honest tính được thì nó cũng tính được** — nên
   mọi kiểu "chứng minh tôi là bản gốc" đều vỡ. Giá trị thật của nó là **nâng giá phải trả**
   và bắt loại cẩu thả. Vì thế nó **chỉ gửi báo động, không bao giờ gửi "mọi thứ ổn"**:
   chuông kêu thì tin được, chuông im không chứng minh điều gì.

Đây cũng là lý do ràng buộc "**hai thiết bị nối trực tiếp, không trung gian**" của đề bài
không chỉ là yêu cầu hình thức: nó gánh luôn phần bảo mật mà HTTP không gánh nổi.

## 8. Kiểm chứng đã thực hiện (13/9/2026)

| Kiểm chứng | Kết quả |
|---|---|
| Test vector chéo Python↔JS (`npm run test:vectors`) | Transcript, chain key, safety number khớp; JS xác minh chữ ký DER của Python và ngược lại; giải mã chéo được |
| mDNS chéo nền tảng | Node.js, Electron, Python cùng hiện trong danh sách LAN của nhau |
| Node.js ↔ Node.js | Ghim khóa 2 chiều → "đã xác minh ✓", safety khớp; chat 2 chiều; gửi ảnh SHA-256 ✓ |
| Electron (bundle đóng gói) ↔ Node.js | Bắt tay, chat 2 chiều đúng |
| Node.js ↔ Python | Bắt tay, chat 2 chiều đúng — cài đặt khác ngôn ngữ vẫn interop |
| PC ↔ điện thoại-web (`/join#k=…`) | Điện thoại tự ghim khóa PC từ QR → "đã xác minh qua QR ✓"; chat 2 chiều |
| Lưu trữ | `identity.json` có `protected: true`; `messages.db` không chứa bản rõ; lịch sử nạp lại sau reconnect |
| Toàn vẹn | Sửa 1 byte bản mã → GCM từ chối giải mã (báo đỏ) |
| Đóng gói | `Sentinell` .exe (NSIS + portable) bằng electron-builder |
| **App mobile (Expo)** | `expo-doctor` 21/21; `expo export` Android bundle 972 module OK |
| **Ghép đôi hai chiều** | Chỉ B quét QR của A một lần → **cả hai** tự ghim nhau kèm địa chỉ; A chủ động “Nhắn lại” B thành công, vẫn `trusted`, không quét lại. Chiều ngược lại (A quét QR của B) cũng cho kết quả tương tự. |
| **Chống phát lại** | Kẻ giả mạo dùng lại `pair_proof` của phiên trước → bị từ chối, không ghim nhầm |
| **Phiên chết** | Một bên rớt mạng/tắt đột ngột → bên kia tự dọn phiên (nhịp tim ping/pong) thay vì kẹt “đang bận” |
| **Mobile ↔ PC** | App mobile bắt tay và **chat hai chiều** với node desktop; safety number **khớp** hai bên; nhật ký giao thức đủ 8 bước; lịch sử lưu **mã hóa at-rest** và nạp lại đúng sau khi khởi động lại app |
| **Máy chủ WebSocket của điện thoại** (`npm run test:wsserver`, 26 mục) | Thư viện `ws` của desktop bắt tay đúng vector RFC 6455; tin chữ UTF-8, nhị phân 300 KB, tin chia 3 khung nguyên vẹn; khung quá lớn → 1009, không mặt nạ → 1002; peer im lặng bị ngắt; một phiên Sentinell thật chạy qua nó |
| **Điện thoại nghe, PC gọi** (`npm run test:phone`, 31 mục) | Node desktop THẬT gọi vào điện thoại: duyệt khóa lạ, giữ chữ ký tới sớm, **ghép đôi hai chiều**, tệp 600 KB/300 KB hai chiều, người thứ ba bị báo bận, chế độ chặt từ chối thẳng, kẻ mạo danh bị phát hiện |
| **Hai điện thoại, không có máy tính** (trong `test:phone`) | Cả hai đầu đều là mã của app mobile: B quét QR của A → A duyệt → ghép đôi hai chiều, safety number khớp, nhắn hai chiều, tệp 400 KB SHA-256 khớp. Chưa quay trên hai điện thoại thật |
| **Bản build Android** (máy ảo Android 16) | PC gọi vào điện thoại → hộp duyệt → chat hai chiều; mDNS thấy chính quảng bá của máy; đang khóa thì không nghe cổng nào; đặt/đổi mật khẩu, sai mật khẩu bị từ chối, xoay khóa khi có mật khẩu vẫn mở lại đúng khóa mới; rời app > 5 phút tự khóa |
| **Chi phí scrypt trên điện thoại** | Bản JS thuần trên Hermes (không JIT): N=2¹⁴ mất **17,7 s** — không dùng được. Bản native (OpenSSL): N=2¹⁴ **153 ms**, N=2¹⁷ **626 ms** → dùng mức OWASP như desktop |

Phát hiện đáng ghi trong quá trình làm: thư viện `cryptography` (Python) sinh chữ ký ECDSA không
chuẩn hóa S (có thể "high-S"), trong khi `@noble` mặc định từ chối để chống malleability — phải
nới `lowS:false` khi xác minh chữ ký của peer Python. Đây là ví dụ thực tế cho [BG 4.8]
"khoảng cách giữa thuật toán đúng và cài đặt an toàn".

## 9. Ánh xạ tính năng ↔ tài liệu

- Mô hình CIA, đe dọa/lỗ hổng/rủi ro: [BG ch.1] — mục 4.
- Diffie–Hellman, ví dụ p=17,g=3: [BG 4.2, 4.4] — `web/demos/dh.html`.
- RSA, chữ ký số: [BG ch.3], [GT ch.3–4] — `web/demos/rsa.html`.
- AES & GCM: [GT 2.5, 2.6.5] — kênh nhắn tin.
- Hàm băm, toàn vẹn: [GT 4.1.2] — safety number, SHA-256 file, `web/demos/hash.html`.
- Mã cổ điển: [GT 2.2] — `web/demos/classical.html`.
- E2EE, làm mới khóa: [BG 4.10]; chống MITM: [BG 4.5]; thư viện kiểm định: [BG 4.8].

## 10. Hạn chế và hướng phát triển

- Giao thức rút gọn theo bài giảng (chưa đầy đủ như Signal X3DH/Double Ratchet); một peer mỗi lúc.
- Điện thoại qua web (`/join`) cố ý không lưu gì — đó là bản cơ bản. Bản đầy đủ là app Android.
- Điện thoại↔điện thoại và mDNS giữa hai máy **thật** đã có mã và đã kiểm từng phần (máy chủ,
  phiên, mDNS trên một máy), nhưng chưa chạy trên hai điện thoại thật cùng WiFi: máy ảo nằm sau
  NAT riêng nên multicast không ra ngoài được.
- iOS trên máy thật ngoài Expo Go cần tài khoản Apple Developer hoặc máy Mac để ký ứng dụng.
