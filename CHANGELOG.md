# Nhật ký phiên bản — Sentinell

Đánh số theo [SemVer](https://semver.org/lang/vi/): `LỚN.NHỎ.VÁ`.

- **LỚN** — đổi kiến trúc hoặc đổi hẳn cách dùng.
- **NHỎ** — thêm tính năng, vẫn tương thích ngược.
- **VÁ** — chỉ sửa lỗi.

> Số phiên bản nằm ở bốn nơi và **phải bằng nhau**: `core/package.json`,
> `desktop/package.json`, `mobile/package.json`, `mobile/app.json`.
> `desktop/package.json` là nơi quyết định tên file `.exe` xuất ra.

---

## 3.17.0 — Bản Android thành "node" đầy đủ: nghe kết nối, tìm LAN, mật khẩu

Trước bản này điện thoại chỉ GỌI ĐI được: máy tính không gọi sang được, hai điện thoại không
nhắn thẳng được cho nhau. Giờ bản Android làm được đủ việc của một node như desktop.

### 1. Điện thoại nghe kết nối — máy chủ WebSocket tự viết (RFC 6455)

React Native có WebSocket để gọi đi nhưng không có cách nào để NGHE. `react-native-tcp-socket`
chỉ cho TCP trần, nên phần bắt tay HTTP Upgrade và khung WebSocket được viết tay trong
`mobile/src/wsproto.js`: khóa `Sec-WebSocket-Accept` (SHA-1 + GUID), khung 7/16/64-bit, bắt buộc
mặt nạ từ client, ghép tin chia nhiều khung, ping/pong, đóng tử tế, nhịp tim phát hiện peer chết.
**Kiểm độ dài trước khi gom byte**: khai 2 GB thì đóng ngay với 1009, không cấp phát gì. Mở cổng
bằng trình duyệt thì nhận 426 kèm lời giải thích thay vì treo.

Phía nhận chạy đúng luồng của desktop (`PeerLink` trong `transport.js` dùng cho cả hai vai):
khóa lạ phải được **duyệt** (hộp Chấp nhận/Từ chối, tự từ chối sau 60 s), **chế độ chặt** từ chối
thẳng, chữ ký tới trước khi duyệt được giữ lại, đang bận thì người thứ ba nhận `busy`.
QR của điện thoại nay mang kèm địa chỉ nghe (`h`, `p`) → máy tính quét là ghim khóa **và gọi
sang luôn**, ghép đôi hai chiều bằng mã một lần như cũ.

**Lỗi chỉ lộ trên máy thật:** `write()` của react-native-tcp-socket chạy bất đồng bộ ở luồng
native còn `end()` đóng ngay ⇒ phản hồi 426 và tin `busy` bị cắt ("Empty reply"). Nay đóng SAU
callback của lần ghi cuối. Bài kiểm có socket giả lập đúng hành vi đó — chạy với mã cũ thì báo
SAI cả hai mục, mã mới thì đạt.

### 2. Tìm máy trong LAN bằng mDNS

`react-native-zeroconf` (Android: NsdManager của hệ điều hành) quảng bá và dò `_sentinell._tcp`
với cùng TXT `id/name/fp/pub` như desktop và bản Python. Khóa trong TXT chỉ để hiển thị — **chỉ
coi là đã ghim khi trùng một liên hệ ghim qua QR**, vì ai cũng quảng bá được tên và khóa bất kỳ.
Trên máy ảo: đăng ký → dò → phân giải → đọc TXT chạy thông (máy thấy chính quảng bá của mình).

### 3. Mật khẩu (chỉ Android)

Như desktop: KEK = scrypt(mật khẩu, muối) → AES-256-GCM bọc `{priv, storage_key}`, thẻ GCM kiêm
kiểm mật khẩu, tham số lưu theo từng tài khoản. Đang khóa thì **không nghe cổng, không quảng bá
mDNS**, không đọc được lịch sử. Rời app quá 5 phút thì tự khóa. Xoay khóa khi có mật khẩu thì
khóa mới được bọc lại (đã kiểm: khóa → mở lại vẫn đúng khóa mới).

**scrypt phải chạy native.** Đo trên máy ảo: bản JS thuần (@noble) trên Hermes mất **17,7 s** cho
mức thấp nhất N=2¹⁴ — Hermes không có JIT. Chuyển sang `react-native-quick-crypto` (OpenSSL, cùng
API `crypto.scrypt` với desktop): N=2¹⁴ còn **153 ms**, và app tự hiệu chỉnh lên **N=2¹⁷ — 626 ms**,
đúng mức OWASP như desktop. Hai bản cho cùng khóa (tài khoản tạo bằng bản JS mở được bằng bản native).

### Sửa kèm
- Bấm nút trong hộp mật khẩu lúc bàn phím đang mở: lần chạm đầu bị `ScrollView` nuốt để ẩn bàn
  phím → `keyboardShouldPersistTaps="handled"`.
- `react-native-tcp-socket` vừa `export default` vừa gán đè `module.exports` → qua Metro `.default`
  là `undefined`; lấy cả hai kiểu.
- Desktop: quét QR khóa có kèm địa chỉ (QR của điện thoại mới) thì gọi sang luôn.

### Kiểm chứng
- `npm run test:wsserver` (26 mục): chính thư viện `ws` của desktop bắt tay, nhắn chữ/nhị phân
  300 KB, tin chia khung, ping, 1009/1002/426/404, nhịp tim, và **một phiên Sentinell thật**.
- `npm run test:phone` (23 mục): **node desktop thật** gọi vào `PeerLink` của điện thoại — duyệt,
  giữ chữ ký sớm, ghép đôi hai chiều, tệp 600 KB/300 KB hai chiều, bận, chế độ chặt, mạo danh.
- Máy ảo Android 16: PC gọi vào qua `adb forward` → hộp duyệt → nhắn hai chiều; đặt/đổi/khóa/mở
  mật khẩu, sai mật khẩu bị từ chối, xoay khóa khi có mật khẩu.
- Chưa kiểm được trên máy ảo: hai thiết bị thật THẤY NHAU qua mDNS (máy ảo nằm sau NAT riêng,
  multicast không ra ngoài) và ĐT↔ĐT qua WiFi — cần điện thoại thật.

---

## 3.16.0 — Bản Android build thật đầu tiên (thoát Expo Go)

`npx expo prebuild` sinh `mobile/android/` từ chính app Expo, nên vẫn **một mã nguồn** cho cả hai.
Build ra `app-release.apk` (66 MB, arm64-v8a + x86_64), chạy trên máy ảo Android 16, **nhắn hai
chiều với node PC** qua `10.0.2.2:8000`: duyệt kết nối → bắt tay → gửi → PC giải mã → trả lời có
dấu tiếng Việt → điện thoại giải mã ✓.

Build thật lộ ra hai lỗi mà Expo Go che mất:

- **Bản release chặn `ws://`.** Android 9+ mặc định cấm lưu lượng không mã hóa; Expo Go và bản
  debug được bật sẵn nên không ai thấy. Bấm "Nối" là `WebSocket` hỏng ngay, gói tin không rời máy.
  Bật `usesCleartextTraffic` qua plugin `expo-build-properties` (không sửa tay `android/`, vì
  prebuild sinh lại). Không làm yếu bảo mật: nội dung đã mã hóa đầu cuối ở tầng ứng dụng, giống
  hệt bản desktop — TLS trên LAN không có CA nào ký cho IP nội bộ.
- **Tiêu đề đè lên thanh trạng thái.** Android 15+ bắt vẽ tràn màn hình (edge-to-edge), mà
  `SafeAreaView` của react-native **chỉ chạy trên iOS**. Chuyển sang `react-native-safe-area-context`;
  màn quét QR để camera tràn màn hình và tự thụt chữ/nút theo insets; bỏ `paddingTop: 50` đặt cứng
  ở phòng chat.

Cách build (Gradle phải chạy bằng **JDK 17** — JDK 25 đi kèm Android Studio làm `prefab` in cảnh
báo "restricted method" ra stderr và AGP coi đó là lỗi):

```powershell
$env:JAVA_HOME = "$env:USERPROFILE\.jdks\zulu17.68.203-ca-jdk17.0.20.1-win_x64"
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
cd mobile\android; .\gradlew.bat assembleRelease "-PreactNativeArchitectures=arm64-v8a,x86_64"
```

Chưa làm (vòng sau): điện thoại tự nghe kết nối (`react-native-tcp-socket`), tìm LAN bằng mDNS
(`react-native-zeroconf`), màn đăng nhập mật khẩu. Chưa kiểm được bàn phím ảo đầy đủ có che ô
nhập hay không (máy ảo đang ở chế độ bàn phím vật lý).

---

## 3.15.0 — Rà soát bảo mật: vá 3 lỗ tự tìm ra

Rà chủ động thay vì chờ gặp. Ba lỗ mới, ngoài `/ui` đã vá ở 3.10.1.

### 1. Làm sập app bằng MỘT gói tin nhỏ (nặng)

`file-meta` do **đối phương** gửi, và ta cấp phát thẳng `new Array(obj.chunks)`. Đối phương
chỉ cần gửi `chunks: 50000000` là bên nhận cấp phát vài GB rồi **chết**. Dính cả ba client:
node desktop, trang `/join`, và app mobile.

*(Đo được: `new Array(50_000_000).fill(null)` → tiến trình Node OOM và chết hẳn.)*

Bắt tay thành công **không** có nghĩa là bên kia thiện chí — khóa của họ có thể đã bị đánh
cắp, hoặc chính họ đổi ý. Nay có `loiMoTaTep()` trong lõi dùng chung: kiểm kiểu, kiểm dải,
chặn tên tệp rác, giới hạn 4 tệp nhận cùng lúc — **kiểm trước khi cấp phát bất cứ thứ gì**.

### 2. Tham số scrypt bị đóng băng vĩnh viễn (âm thầm, nhưng hiểm)

`N`, `r`, `p` vẫn được **ghi** vào `identity.json`, nhưng `_dansuatKek()` **chẳng bao giờ đọc
lại** — lần nào cũng dẫn bằng tham số hiện hành. Hệ quả: hễ ai đó nâng tham số lên là **mọi
tài khoản đã tạo trở nên không mở được nữa**, mất cả khóa danh tính lẫn lịch sử. Tức là tham
số bị khóa chết ở mức cũ, không bao giờ nâng được.

Nay khóa được dẫn bằng **tham số đã lưu của chính tài khoản đó**. Nhờ vậy nâng được mặc định
lên **N = 2¹⁷** theo khuyến nghị OWASP cho scrypt *(đo trên máy thật: 2¹⁵ → 115 ms,
2¹⁶ → 232 ms, 2¹⁷ → 468 ms — 128 MB mỗi lần thử)*. Tài khoản cũ vẫn mở bình thường; **đổi
mật khẩu** là dịp nâng lên mức mới.

Kèm một hệ quả tinh vi: bọc lại gói sau khi **xoay khóa** trước đây ghi tham số *mới* trong
khi bản mã lại do KEK của tham số *cũ* tạo ra → lần mở sau ra khóa khác. Nay gói luôn mang
đúng bộ tham số khớp với KEK đang giữ.

### 3. Bề mặt web chỉ khóa một nửa

3.11.0 chỉ khóa `/join`, `/js`, `/css`, `/vendor` theo mạng con. Còn lại **vẫn mở cho cả LAN**:

- `/` và `/index.html` — **trang giao diện desktop**
- `/demos/*` — các trang demo thuật toán
- `/api/info` — và đường này khai ra **danh sách đầy đủ card mạng của máy** kèm nhãn phân
  loại, tức lộ cấu trúc mạng nội bộ cho bất kỳ ai cùng WiFi

Nay khóa **toàn bộ** tầng HTTP theo cùng một quy tắc. `/file/*` vẫn chặt hơn: chỉ loopback.

### Đã soi và KHÔNG có vấn đề

- **XSS**: mọi `innerHTML` đều qua `esc()`; toast dùng `textContent`. Tên thiết bị do đối
  phương đặt không chèn được HTML vào giao diện.
- **Đường dẫn tệp**: `path.basename()` + lọc `..` + tiền tố ngẫu nhiên.
- **Phát lại gói cũ**: khóa mỗi tin dẫn từ chain key *hiện tại*, nên gói cũ giải mã hỏng;
  bỏ gói giữa chừng cũng làm lệch chain key ⇒ phát hiện ngay.
- **Thông báo Windows**: vẫn chỉ mang LOẠI sự kiện, không tên, không nội dung.

`npm run test:lan` **58 mục**, `npm run test:account` **62 mục**. Tất cả 6 bộ đạt.

---

## 3.14.0 — Bẫy dây trong mã web: bắt kẻ tấn công lười

Ý tưởng "cài phản gián ngay trong JS". Phần **giả dạng** thì không chạy được — tệp JS được
phục vụ công khai cho mọi máy trong mạng con, kẻ tấn công tải về đọc kỹ rồi mới ra tay, nên
giấu kiểu gì cũng vô ích. Có một định lý chặn mọi biến thể: **thứ gì mã honest tính được thì
kẻ tấn công cũng tính được**, vì nó cầm sẵn mã honest. Mọi kiểu "chứng minh tôi là bản gốc"
(tự băm, ký, giải câu đố từ máy tính) đều vỡ ở đúng chỗ đó. Và **"trang tự kill chính nó"**
cũng vô nghĩa: mã đã bị sửa thì nó không tự sát.

Nhưng lõi của ý tưởng thì đúng. Kẻ tấn công **lười** không đọc mã — nó dùng đòn tổng quát:
ghi đè `WebSocket.prototype.send` (hoặc `fetch`, `JSON.stringify`, `crypto.getRandomValues`…)
để chép bản rõ **trước khi** mã hóa. Đòn đó ăn với mọi bản dựng mà không cần hiểu gì — và nó
**để lại dấu**: hàm bị ghi đè không còn là `[native code]`.

*(Đo được: ghi đè thường → bẫy **bắt được**; kẻ ghi đè luôn cả `Function.prototype.toString`
→ **qua mặt được**. Đúng như mong đợi: bắt kẻ lười, thua kẻ có chuẩn bị.)*

Trang `/join` nay rà 7 hàm nền tảng cộng với các thẻ `<script>` lạ trên trang.

### Hai quyết định thiết kế quan trọng

**Chỉ gửi báo động, KHÔNG BAO GIỜ gửi "mọi thứ ổn".** Chuông kêu thì tin được; chuông im
không có nghĩa gì. Làm vậy để sau này **không ai dựng được** một dấu "✅ đã xác minh" lên
trên nó — thứ mà kẻ tấn công có chuẩn bị giả được trong một dòng.

**Báo động đi qua đường ĐÃ MÃ HÓA**, không phải gói trần. Muốn bịt miệng thì phải bỏ hẳn một
gói — mà bỏ gói là `seq` bên kia lệch và máy tính cảnh báo ngay; sửa gói thì GCM từ chối.

### Phản ứng nằm ở phía máy tính

Nhận báo động là máy tính **ngắt phiên** ngay, ghi `verify-fail` vào nhật ký giao thức, và
hiện cảnh báo đỏ nói rõ dấu hiệu nào, gợi ý chuyển sang nối trực tiếp, **và nhắc luôn rằng
tiện ích mở rộng của trình duyệt cũng gây ra được** — để người dùng không hoảng nhầm.

Kiểm chứng bằng tấn công thật trên trình duyệt: ghi đè `WebSocket.prototype.send` rồi bấm
kết nối → phiên bị ngắt trong vài giây, trước khi kịp gõ tin nhắn nào. Nhánh sạch thì kết
nối và nhắn tin bình thường. `npm run test:lan` nay **47 mục**, có mục
*"phiên bị NGẮT thật, không chỉ cảnh báo suông"*.

**Nói cho rõ:** đây là **bẫy dây**, không phải bảo vệ. Nó nâng giá phải trả cho kẻ tấn công
và bắt được loại cẩu thả. Kẻ đọc mã trước rồi gỡ bẫy vẫn đi qua được. Đường an toàn thật sự
vẫn chỉ có hai: **nối trực tiếp** hoặc **dùng bản cài đặt**.

---

## 3.13.0 — Rà dấu vết kẻ đứng giữa, ngay trong lúc ghép đôi

### Điều KHÔNG làm được (và vì sao)

Không kiểm tra được tệp `join.js` trên điện thoại có bị sửa hay không. Muốn kiểm thì phải
hỏi chính đoạn mã đã bị sửa — **kẻ gian tự chấm bài của mình**. Mọi biến thể đều vỡ ở đúng
chỗ này: băm rồi đối chiếu, ký rồi xác minh, hỏi vọng từ máy tính sang… tất cả đều phải chạy
bằng đoạn mã ta không tin.

### Điều LÀM ĐƯỢC: bắt dấu vết, không bắt hành vi

Kẻ tấn công muốn chen vào giữa hai máy trong LAN thì cách phổ biến nhất là **giả mạo ARP**:
nó nói với máy bạn "tôi là router", nói với router "tôi là điện thoại kia". Việc đó để lại
dấu vết **ngay trên máy này**, trong bảng láng giềng:

- **một địa chỉ MAC đứng tên nhiều IP** → gần như chắc chắn là giả mạo
- **MAC của một địa chỉ đổi giữa chừng** → có kẻ vừa chen vào

Thêm một tín hiệu độc lập: **ai đã tải mã của chế độ web** trong lượt ghép đôi này. Người
dùng biết rõ mình cầm mấy cái điện thoại — thấy *2 thiết bị* trong khi chỉ có 1 là dấu hiệu rõ.

Kết quả hiện ngay trong cửa sổ QR và **tự làm mới mỗi 4 giây** khi cửa sổ đang mở, nên phát
hiện xảy ra trước khi người dùng kịp gõ tin nhắn đầu tiên — đúng như mong muốn.

### Không hứa quá

Dòng kết quả ghi rõ: *"Chỉ bắt được kiểu tấn công phổ biến nhất — không thấy gì **không có
nghĩa là** chắc chắn an toàn."* Nó không bắt được điểm phát sóng giả, cũng không bắt được
trường hợp chính router bị chiếm. Một dòng "✅ An toàn" ở đây sẽ nguy hiểm hơn là không rà,
vì nó khiến người dùng yên tâm sai chỗ.

Bảng ARP thô gần như toàn multicast (`224.0.0.x` dùng chung MAC `01-00-5E-…`) — không lọc
thì lần rà nào cũng báo động giả. Chỉ xét **unicast, cùng mạng con đang chia sẻ**.

Phần phân tích tách rời khỏi phần đọc hệ thống (`phanTichLangGieng`) để kiểm thử được bằng
bảng giả — không phải chờ có kẻ tấn công thật mới biết nhánh cảnh báo có chạy hay không.
`npm run test:lan` nay **41 mục**, gồm cả *"trùng MAC ở mạng con khác → KHÔNG báo động nhầm"*.

---

## 3.12.1 — Máy chỉ có LAN: nối trực tiếp bằng cáp USB

Tình huống khó nhất: máy tính **không có card WiFi** (chỉ cắm dây, đang ở mạng trường/công ty),
điện thoại là **iPhone** nên buộc dùng chế độ web. Lúc này *cả hai* chiều điểm phát sóng đều
bế tắc — máy không phát được, mà cũng không nối vào hotspot của điện thoại được.

Lối thoát: **cắm cáp USB**. iPhone chia sẻ mạng qua cáp, Windows hiện thêm một card Ethernet
mang đúng dải `172.20.10.x/28` (iOS dùng chung dải này cho WiFi, USB và Bluetooth). Chỉ có sợi
cáp giữa hai máy — không sóng, không ai chen vào được. Đây là đường an toàn nhất trong mọi
phương án, và bộ phân loại **đã nhận ra sẵn** vì nó xét theo dải địa chỉ chứ không theo tên card.

### Hai lỗi lộ ra khi kiểm tình huống này

- **Mã QR mặc định chọn nhầm đường.** Điểm ưu tiên của đường trực tiếp chỉ hơn mạng chung
  vài điểm, nên may thì thắng: mạng trường `10.x` thì cáp USB thắng 30–28, nhưng mạng nhà
  `192.168.x` thì **mạng chung thắng 32–30** và mã QR trỏ vào đúng đường kém an toàn hơn.
  Nay đường trực tiếp được +60 — thắng áp đảo, không còn phụ thuộc may rủi.
- **iPhone chia sẻ qua Bluetooth bị loại oan.** Card Bluetooth nằm trong danh sách "card ảo"
  bị phạt −100 (vì thường là card rác), nên dù mang địa chỉ `172.20.10.x` thật nó vẫn xếp
  chót. Nay nếu card đang mang địa chỉ của một đường trực tiếp thì **không phạt** — nó là
  đường thật, và là đường an toàn nhất.

### Giao diện

Hướng dẫn nêu đủ **ba** cách nối trực tiếp (máy phát / điện thoại phát qua WiFi / cáp USB),
và nếu máy **đang có sẵn** một đường trực tiếp mà người dùng lại chọn đường khác thì hiện
thẳng: *"👉 Máy này đang có sẵn đường nối trực tiếp: chọn 172.20.10.2 ở ô trên là xong."*

---

## 3.12.0 — Điểm phát sóng chiều ngược lại, và cảnh báo mạng công cộng

### Lối thoát cho máy không phát được hotspot (và cho iPhone)

3.11.0 khuyên "bật điểm phát sóng trên máy tính" — nhưng rất nhiều máy **không phát được**
(card WiFi không hỗ trợ, đang nối bằng dây, hoặc bị chính sách chặn). Mà iPhone thì chưa có
app riêng nên buộc phải dùng chế độ web. Gặp đúng hai điều kiện đó thì lời khuyên cũ **bế tắc**.

Thực ra điểm phát sóng chạy được **cả hai chiều**: máy tính không phát được thì **điện thoại
phát**, máy tính nối vào. An toàn y hệt — vẫn chỉ hai máy trên một đoạn mạng, không ai chen
vào giữa. Bộ phân loại nay nhận ra chiều đó:

| Dải | Là gì | Vì sao nhận ra chắc chắn |
|---|---|---|
| `192.168.137.x` | máy tính phát (Windows ICS) | dải cố định từ thời XP |
| `172.20.10.x` **mặt nạ /28** | **iPhone phát** (Điểm truy cập cá nhân) | iOS cố định dải này, và `/28` rất đặc trưng — phải khớp cả mặt nạ mới gắn nhãn xanh |
| `192.168.43.x` | **Android phát** | dải tethering gốc của Android |

Nhãn cũng **nói rõ nhận ra cái gì** ("Điểm truy cập cá nhân của iPhone") để người dùng tự
kiểm chứng phán đoán của app, chứ không phải tin suông.

Lời khuyên trong cửa sổ QR nay nêu **cả hai chiều**, kèm đúng dải địa chỉ cần chọn cho từng
chiều.

### Mạng công cộng: phải xác nhận rồi mới hiện mã QR

Ở mạng Windows đánh dấu `Public`, mã QR **bị ẩn** cho tới khi người dùng tích vào ô xác nhận
đã hiểu rủi ro. Không chặn hẳn — có lúc thật sự không còn lựa chọn nào khác — nhưng không để
ai làm mà không biết mình đang làm gì.

Ô xác nhận đặt **sau** phần giải thích: bắt xác nhận trước khi cho đọc lý do là vô nghĩa.
Chỗ mã QR bị ẩn có một dòng chỉ xuống dưới, kẻo người dùng tưởng app hỏng.

### Chế độ web chỉ mở trong lúc ghép đôi

Mã web nằm phơi 24/7 thì kẻ tấn công muốn ra tay lúc nào cũng được. Nay nó chỉ mở **30 phút
sau mỗi lần mở cửa sổ QR** — kẻ tấn công phải có mặt và ra tay đúng khoảnh khắc bạn thật sự
đang ghép đôi. Đang trò chuyện với một máy web thì cửa vẫn mở, kẻo trình duyệt điện thoại
nạp lại trang giữa chừng là đứt.

`npm run test:lan` nay 29 mục, gồm mục **"172.20.10.x nhưng sai mặt nạ → không dám gắn nhãn
an toàn"** — giữ đúng nguyên tắc thà báo nhầm "cẩn thận" còn hơn báo nhầm "an toàn".

---

## 3.11.0 — Nhận diện loại mạng, và khóa chế độ web theo card mạng

Hai lớp gia cố cho điểm yếu duy nhất còn lại của chế độ web: **mã JavaScript của `/join` đi
qua HTTP nên ai đứng trên đường đều sửa được**, và khi đó mã hóa đầu cuối còn nguyên nhưng
vô dụng — vì một "đầu" đã là mã của kẻ tấn công. Không có cách vá bằng mật mã (mã đã bị sửa
thì tự kiểm tra chính nó cũng vô nghĩa), nên cả hai lớp đều nhắm vào **ai được phép ở trên
đường**, chứ không cố phát hiện tấn công.

### Nhận diện mạng công cộng / mạng riêng / nối trực tiếp

Cửa sổ QR nay gắn nhãn cho **đúng đường đang chia sẻ**:

| Nhãn | Khi nào | Nguồn tin |
|---|---|---|
| ✅ **Nối trực tiếp** | địa chỉ thuộc `192.168.137.x` | dải cố định của Windows Mobile Hotspot/ICS từ thời XP — thấy dải này gần như chắc chắn là điểm phát sóng của chính máy |
| ⚠️ **Mạng riêng** | Windows đánh dấu `Private` | `Get-NetConnectionProfile` |
| 🚫 **Mạng công cộng** | Windows đánh dấu `Public` | `Get-NetConnectionProfile` |
| 🚫 **Chưa rõ / chưa có mạng** | chưa đọc được, hoặc `169.254.x.x` | — |

Không tự đoán lại thứ Windows đã biết: người dùng đã trả lời "mạng này công cộng hay riêng
tư" ngay lúc nối vào lần đầu, dùng luôn câu trả lời đó.

**Nguyên tắc khi phân loại: nghi ngờ thì báo nguy.** Báo nhầm "cẩn thận" chỉ gây phiền; báo
nhầm "an toàn" là đẩy người dùng vào đúng chỗ nguy hiểm. Nên chỉ dải hotspot mới được gắn
nhãn xanh, còn lại mặc định là cảnh báo. Có bài kiểm thử riêng cho đúng tính chất này.

Gọi PowerShell mất **~3,5 giây**, nên đọc nền ngay lúc khởi động và đệm lại — mở cửa sổ QR
là nhãn đã nằm sẵn, không phải chờ.

### Khóa chế độ web theo card mạng

Người dùng chọn địa chỉ nào trong mã QR thì **chỉ mạng con đó tải được mã của chế độ web**
(`/join`, `/js`, `/css`, `/vendor`); nơi khác nhận **403 kèm trang giải thích phải làm gì**.

Bật điểm phát sóng rồi chọn `192.168.137.1` là kẻ ở WiFi gốc **không tải nổi `join.js`** để
mà sửa. Không phải phát hiện tấn công — mà là làm cho nó không với tới được.

Card đã chọn biến mất (tắt điểm phát sóng, rút cáp) thì **rơi về card còn sống** thay vì
khóa cứng mọi đường rồi để người dùng ngồi đoán vì sao.

`npm run test:lan` bổ sung 13 mục, gồm cả kiểm **tầng HTTP có thật sự hỏi hàm quyết định
hay không** — chứ không chỉ kiểm bản thân hàm đó.

---

## 3.10.1 — VÁ LỖ HỔNG: kênh điều khiển `/ui` mở ra toàn mạng LAN

Tìm ra khi đang phân tích câu hỏi "ai bắt được gói tin có đọc được không". Câu trả lời cho
*gói tin* là không — nhưng hóa ra kẻ tấn công **không cần** bắt gói tin.

Máy chủ bind `0.0.0.0` (bắt buộc, để điện thoại vào được `/join`), mà `server.on("upgrade")`
**không kiểm tra gì** trước khi nhận WebSocket `/ui`. Nên bất kỳ máy nào cùng mạng chỉ cần
mở `ws://<ip-máy-bạn>:<cổng>/ui` là:

- đọc được toàn bộ trạng thái: tên, khóa công khai, vân tay, danh bạ đã ghim
- **ra được mọi lệnh**: `load_history` (đọc sạch lịch sử tin nhắn đã giải mã),
  `send_text` (gửi tin thay bạn), `delete_chat`, `rotate_key`, `export_account`…

Không cần phá mã hóa, không cần đứng giữa, không cần sửa JS. Chỉ cần cùng WiFi và biết cổng.
Toàn bộ công sức mã hóa đầu cuối, ghim khóa, mật khẩu — đi vòng qua hết.

*(Đo được trước khi vá: từ một tiến trình khác nối qua IP LAN → nhận được `state` đầy đủ, rồi
gửi `set_name` và tên thiết bị đổi thật.)*

**Vá:** `/ui` và `/file/*` nay **chỉ nhận loopback**. Giao diện thật luôn chạy ở `127.0.0.1`
nên không mất gì; trang `/join` dựng tệp bằng `blob:` ngay trong trình duyệt nên cũng không
cần `/file`. Những đường điện thoại thật sự cần (`/join`, `/api/info`, mã lõi) vẫn mở.

Chỉ tin **loopback**, không tin IP LAN của chính máy: gói tin gửi tới địa chỉ đó đã đi qua
card mạng, tức là người khác cũng gửi tới đó được.

Thêm `npm run test:lan` — bài kiểm tra thường trực về **những gì node phơi ra mạng**, gồm cả
hai chiều: đường nào phải chặn, và đường nào phải còn mở.

---

## 3.10.0 — Cột trò chuyện khớp với tìm kiếm, gộp sao lưu vào mật khẩu

### Cuộc trò chuyện "vô hình" — lỗi mà tìm kiếm phơi ra

Cột trò chuyện dựng từ **danh bạ** (khóa đã ghim qua QR), trong khi ta nhắn được với cả
thiết bị **chưa ghim** (họ gọi sang, mình bấm Chấp nhận). Những cuộc đó có lịch sử lưu trên
máy nhưng **không có chỗ nào trong danh sách** — mà tìm kiếm thì vẫn moi ra. Nhìn đúng như
app tự nhớ những thứ người dùng tưởng đã không còn.

Nay cột trò chuyện lấy từ `listConversations()`: **mọi cuộc còn lịch sử**, đã ghim hay chưa,
kể cả lịch sử "mồ côi" của kho từ bản cũ. Dấu ✓ chỉ dành cho khóa đã ghim.

Kèm theo: bấm vào một cuộc không có địa chỉ để gọi (điện thoại dùng trình duyệt, hoặc kho
cũ) nay **mở lại lịch sử** thay vì chỉ báo lỗi — lịch sử nằm sẵn trên máy, đọc được ngay.

Đổi `state.contacts` thành "mọi cuộc trò chuyện" kéo theo một cái bẫy: ba chỗ dùng danh sách
đó để khẳng định **"khóa này đã xác minh qua QR"** — khối *Đã ghim qua QR*, huy hiệu ở hộp
duyệt kết nối, và `expect_pub` lúc gọi sang. Để nguyên thì app nói dối rằng một khóa chưa
xác minh đã được xác minh, đúng thứ mà cơ chế ghim sinh ra để chặn. Cả ba nay đi qua
`daGhim()` — lọc theo `c.pinned`.

### Sao lưu và mật khẩu gộp làm một

Trước đây có ba thứ chồng chéo: `💾 Sao lưu` (xuất khóa bí mật **dạng bản rõ**), `💾 Xuất tài
khoản` (đã mã hóa), và mật khẩu. Đặt mật khẩu cho app xong mà một cú bấm là lộ sạch khóa bí
mật thì coi như không đặt.

Nay chỉ còn **một cặp nút**: `💾 Sao lưu` và `↩️ Phục hồi từ tệp`, tệp `.sen` **luôn được mã
hóa bằng mật khẩu**.

- Máy đã đặt mật khẩu → dùng luôn gói sẵn có.
- Máy chưa đặt → hỏi một mật khẩu riêng cho tệp, **không** biến nó thành tài khoản của máy.
- Phục hồi nhận cả tệp `.sen` lẫn bản sao lưu bản rõ đời cũ (có cảnh báo). Nhưng **màn khóa
  thì chỉ nhận `.sen`** — cho nhập tệp bản rõ lúc đang khóa là mở toang một đường vòng qua
  màn khóa.

### Sửa lỗi giao diện

- **Ô tìm kiếm**: viền lúc bấm vào bị cắt cụt ở cạnh trên. Hai nguyên nhân chồng nhau — ô nằm
  *bên trong* vùng cuộn nên viền bị mép vùng cuộn xén, và viền vẽ loe ra ngoài. Nay ô nằm
  **ngoài vùng cuộn** (không còn hàng nào trôi lấp ló phía sau) và viền vẽ **thụt vào trong**
  (`outline-offset: -2px`), nên không còn gì cắt được nó.
- Chỗ tô sáng trong **tên** liên hệ rơi về màu vàng mặc định của trình duyệt trong khi chỗ tô
  trong nội dung là màu nhấn — do luật chỉ viết cho `.sr-text mark`. Nay dùng `.sr-item mark`.

Bổ sung 15 mục kiểm thử trong `npm run test:account`, gồm mục *"MỌI kết quả tìm được đều mở
lại được từ cột trò chuyện"* — chính là bất biến mà lỗi trên đã phá vỡ.

---

## 3.9.0 — Mục "Đã xóa", tài khoản cục bộ, và sửa thanh tìm kiếm

### Mục "Đã xóa" — xóa có đường lùi

Trước đây xóa cuộc trò chuyện là mất luôn, chỉ chặn bằng đúng một hộp `confirm()`.
Nay nó **chuyển vào mục 🗑 Đã xóa** ở cuối danh sách trò chuyện, và ở đó có hai lựa chọn:
**khôi phục** hoặc **xóa vĩnh viễn**.

- Tin đã xóa **không hiện ra khi tìm kiếm**, không có trong lịch sử, không có ở dòng xem
  trước. Cách làm: thêm cột `deleted_at`, mọi truy vấn thường đều lọc `deleted_at IS NULL`
  — chặn ở tầng kho chứ không phải lọc ở giao diện, nên không còn lối nào cho nó lọt lại.
- Khôi phục trả lại **đúng trạng thái cũ**, kể cả việc khóa đó trước đây có được ghim qua QR
  hay chưa — không tự dưng phong một liên hệ chưa xác minh thành đã xác minh.
- **Xóa vĩnh viễn thì chạy thêm `VACUUM`.** `DELETE` của SQLite chỉ đánh dấu trang là trống
  chứ không xóa bytes: khóa công khai của người kia, mốc thời gian và cả bản mã vẫn nằm
  nguyên trong tệp `.db`. Nội dung thì đã mã hóa, nhưng "đã nói chuyện với ai, lúc nào,
  bao nhiêu tin" cũng là thứ cần giấu. `VACUUM` dựng lại tệp, bỏ hẳn phần trống đó.
  *(Đo được: trước khi vá, khóa công khai của liên hệ đã xóa vẫn tìm thấy trong tệp .db.)*

### Tài khoản cục bộ (mật khẩu)

Đặt được mật khẩu cho máy này ở tab **🔑 Khóa**. Từ đó mỗi lần mở app phải nhập mới dùng được.

```
mật khẩu --scrypt(N=2¹⁵, r=8, p=1, salt 16B)--> KEK 32B
identity.json chỉ còn:  AES-256-GCM(KEK, {priv, storage_key})
```

- **Khác gì với trước**: không đặt mật khẩu thì khóa bí mật chỉ được `safeStorage` (DPAPI)
  bọc, mà DPAPI gắn với **tài khoản Windows** — ai đăng nhập được vào máy bằng tài khoản của
  bạn là mở được. Đặt mật khẩu thì phải biết mật khẩu, không có đường vòng.
- scrypt cố ý tốn **cả thời gian lẫn bộ nhớ** (~32 MB mỗi lần thử) nên dò hàng loạt bằng GPU
  trở nên rất đắt. Thẻ xác thực GCM đóng luôn vai trò kiểm mật khẩu — không lưu thêm "giá trị
  kiểm tra" nào, thứ chỉ tổ giúp kẻ dò thử nhanh hơn.
- **Đang khóa thì không lộ gì**: `state` gửi về giao diện chỉ có `locked: true` (không tên,
  không danh bạ); `/api/info` chỉ trả `{locked:true}`; mDNS **chưa quảng bá**; ai gọi `/peer`
  thì bị từ chối tử tế kèm lý do thay vì ngồi chờ một handshake không bao giờ tới.
- **Xoay khóa khi đang có tài khoản** sẽ bọc lại gói — nếu không, lần mở sau lấy ra đúng cái
  khóa vừa bị thay.
- Kèm **Khóa ngay**, **Đổi mật khẩu**, **Bỏ mật khẩu**.
- **Xuất tài khoản sang máy khác**: tệp `.sen` mang khóa danh tính (vẫn nằm trong gói
  scrypt+GCM) và danh bạ; lộ tệp mà không có mật khẩu thì vẫn vô dụng. Màn khóa có sẵn lối
  "Máy mới? Nhận tài khoản từ tệp". **Lịch sử tin nhắn không đi kèm** — tệp này là danh tính,
  không phải bản sao lưu dữ liệu.

Hộp nhập mật khẩu phải tự dựng: **Electron không có `window.prompt`** (gọi là trơ, không hiện
gì cả), trong khi `confirm()`/`alert()` thì vẫn chạy.

### Sửa lỗi giao diện

Thanh tìm kiếm ở 3.8.0 lấy nền `--rail` trong khi cột bên cạnh là `--surface` — ở nền tối
thành một vệt tối hơn, lệch hẳn. Nay dùng đúng `--surface`, và biểu tượng 🔎 với nút ✕ được
bọc lại để bám vào **ô nhập** thay vì vào lề thanh. *(Đo được: nền hai bên nay bằng nhau,
mép trái ô nhập thẳng hàng với tiêu đề "Trò chuyện".)*

Mục Đã xóa: hai nút xuống dòng khi hẹp thay vì bóp tên liên hệ còn "Laptop phòng thí n…".

Thêm bộ kiểm thử `npm run test:account` (45 mục), trong đó có **kiểm nâng cấp từ kho đời cũ**
— máy đang dùng bản ≤ 3.8.0 chưa có cột `deleted_at`, mở bằng bản mới phải tự thêm cột chứ
không được làm hỏng lịch sử.

---

## 3.8.0 — Tìm kiếm trong tin nhắn

Ô tìm ngay đầu cột trò chuyện, tìm **cả tên liên hệ lẫn nội dung tin nhắn** (kể cả tên tệp
đã gửi/nhận).

- **Gõ không dấu vẫn ra chữ có dấu**: "bao cao" tìm thấy "Báo cáo", "do an" tìm thấy "đồ án".
  Bỏ dấu bằng `NFD` rồi lọc dấu thanh, riêng **đ/Đ** phải xử lý tay vì không tách được.
  Chỗ khớp được tô đậm, nhưng cắt trên chuỗi **gốc** nên chữ hiện ra vẫn còn nguyên dấu.
- Kết quả là đoạn trích **quanh** từ khóa (≈40 chữ trước, 90 chữ sau), không phải cả tin nhắn.
- Bấm vào kết quả thì **mở đúng cuộc trò chuyện và nháy sáng đúng bong bóng đó**.

Kèm theo là **chế độ xem lại** (chỉ đọc): lịch sử nằm sẵn trên máy nên không cần bắt tay mới
đọc được. Trước đây chỉ mở được cuộc trò chuyện đang kết nối — tìm ra tin nhắn của một thiết
bị đang tắt thì bấm vào cũng chẳng tới đâu. Nay mở ra xem được, ô nhập tin thay bằng thanh
*"Chỉ xem lại lịch sử — chưa kết nối với …"* kèm nút **Kết nối để nhắn**.

**Vì sao không dùng `LIKE` của SQL**: nội dung tin nhắn được **mã hóa at-rest** (AES-256-GCM,
khóa lưu trữ cục bộ), trong `messages.db` chỉ là bytes ngẫu nhiên — `LIKE` không khớp được gì.
Nên tìm kiếm phải giải mã từng dòng rồi so trong bộ nhớ: chậm hơn, nhưng đó chính là **cái giá
và cũng là mục đích** của việc mã hóa kho — ai lấy được tệp .db cũng không tìm được gì trong
đó. Bộ kiểm thử chứng minh điều này bằng cách đọc thẳng tệp .db và xác nhận không có chữ nào
ở dạng đọc được. Để bù, việc quét đi từ **mới về cũ** và dừng khi đủ 60 kết quả.

Trên điện thoại (React Native): nút 🔎 trong phòng chat lọc ngay lịch sử đã nạp của cuộc trò
chuyện đang mở. Trang `/join` (điện thoại dùng trình duyệt) **không có** tìm kiếm — chế độ đó
cố ý không lưu lịch sử nên chẳng có gì để tìm.

Thêm bộ kiểm thử `npm run test:search`.

---

## 3.7.0 — Gửi tệp bằng khung nhị phân (bỏ base64)

Tệp trước đây đi qua **hai lớp mã hóa chuỗi chồng nhau**: nội dung tệp phải base64 (+33%)
mới nhét được vào JSON, rồi bản mã lại in ra chuỗi hex (+100%). **1 byte tệp hóa 2,67 byte
trên dây** — và bản thân việc dựng/đọc chuỗi đó còn tốn hơn cả AES, nên tệp từ 10 MB trở lên
là giao diện đứng hình.

Nay khối tệp đi bằng **khung nhị phân** riêng, gửi thẳng bytes:

```
"SNT1" | dir(1) | độ dài mtype(1) | seq(4, BE) | mtype utf8 | bản mã GCM
bản mã = GCM( u16BE(độ dài meta) ‖ meta JSON ‖ bytes thô )
```

- **Bảo mật không đổi**: vẫn mỗi khối một khóa ratchet riêng, vẫn AES-256-GCM, vẫn kiểm
  toàn vẹn SHA-256 cả tệp. Phần đầu khung chỉ để lộ đúng những trường mà gói JSON vốn cũng
  để lộ (`seq`, `dir`, `mtype`) — phải biết chúng mới dựng được AAD. **Tên tệp nằm trong
  vùng đã mã hóa**, y như trước.
- AAD của khung nhị phân có thêm `bin:1` để **không thể tráo** một khung nhị phân thành gói
  JSON cùng `seq`/`mtype` (và ngược lại) — GCM từ chối ngay.
- **Tự thương lượng**: hai bên khai `feat: ["bin"]` trong handshake. Gặp peer chưa hiểu
  (node Python tham chiếu) thì **tự lùi** về đường JSON+base64 cũ, không hỏng gì.
- Chặng trong máy (giao diện ↔ node) cũng bỏ base64: tệp đi bằng một khung
  `u16BE(độ dài phần đầu) ‖ phần đầu JSON ‖ bytes`.
- **Dải tiến độ** khi gửi/nhận, và **chặn ở 200 MB** kèm lời giải thích thay vì im lặng hỏng.
- Có **chờ hàng đợi socket vơi** trước khi nhồi tiếp, nên bộ nhớ không phình theo kích thước
  tệp khi mạng chậm.

Đo được (8 MB giữa hai node trên cùng máy, `npm run test:file`):

| | byte trên dây / byte tệp | thời gian |
|---|---|---|
| đường cũ (JSON+base64) | **2,67** | 2,37 s |
| khung nhị phân | **1,00** | 0,90 s |

Kiểm chứng: gửi đúng qua giao diện thật ở cả bốn chiều (máy tính↔máy tính, điện thoại→máy
tính, máy tính→điện thoại), tệp 90 MB tới nơi khớp từng byte, hai tệp gửi chồng nhau vẫn
ghép đúng, nhắn chữ sau khi truyền tệp vẫn giải mã được (ratchet còn khớp). Vector kiểm thử
chéo Python↔JS vẫn đạt toàn bộ.

Thêm hai bộ kiểm thử: `npm run test:binary` (khung nhị phân ở lõi) và `npm run test:file`
(gửi tệp thật giữa hai node, đo byte trên dây).

---

## 3.6.0 — Rà lại toàn bộ câu chữ trên giao diện

Lỗi nặng nhất: **hai nút nghĩa ngược nhau mà chữ gần giống hệt**, nằm ngay trong cùng một
luồng ghép đôi — `💾 Tải ảnh QR về` (lưu xuống) và `Tải ảnh QR` (chọn ảnh lên). Tiếng Việt
"tải" vừa là lên vừa là về, nên người dùng không thể đoán đúng bằng cách đọc. Nay mỗi nút
một động từ riêng: **`💾 Lưu ảnh QR`** và **`🖼️ Chọn ảnh QR`**; câu hướng dẫn cũng gọi đúng
tên nút ở phía bên kia.

- Bỏ 8 chỗ thuật ngữ lập trình lọt ra giao diện: `node cục bộ đã sẵn sàng` → `sẵn sàng`;
  `Tự phát hiện qua mDNS` → `Các thiết bị cùng mạng tự thấy nhau`; `tin-khi-dùng-lần-đầu`
  (dịch sát chữ của TOFU) bỏ hẳn; `toàn vẹn hỏng` → nói rõ chuyện gì xảy ra; …
- Thêm `dichLoiMang()`: `ECONNREFUSED` → *"thiết bị đó không mở Sentinell, hoặc đang dùng
  cổng khác."*, `EHOSTUNREACH` → *"kiểm tra hai bên có cùng WiFi/hotspot không."*
- Thống nhất cách gọi: **"thiết bị kia"**, **"cuộc trò chuyện"**.
- **Cố ý giữ** thuật ngữ *safety number* / *vân tay* (khớp báo cáo môn học, có thêm chú
  thích) và giữ nguyên **nhật ký giao thức** đầy đủ `GCM`/`seq`/`ECDSA` — đó chính là chỗ
  phơi bày mật mã để thuyết trình.

---

## 3.4.0 – 3.5.1 — Thông báo pop-up của riêng Sentinell

*(Gộp lại một mục: ba bản này cùng làm một việc, ghi bổ sung sau.)*

Toast của Windows không chuyển được cú bấm về cho bản portable (đã thử ba cách ở 3.3.1 mà
vẫn không ăn), nên bỏ hẳn toast hệ thống và **tự dựng cửa sổ thông báo** (`desktop/popup.js`).
Cú bấm khi đó là chuyện nội bộ của app nên chắc chắn tới nơi. Đổi lại, thông báo không vào
trung tâm thông báo Windows và không hiện trên màn hình khóa — với app nhắn tin mã hóa đầu
cuối thì đó lại là điều tốt.

- Góc bo sâu kiểu kính, viền sáng mảnh — và cửa sổ rộng hơn tấm thẻ để góc tròn không bị cắt.
- **Âm thanh báo**: chuông hai nốt dựng bằng Web Audio, không cần kèm tệp âm thanh nào.
- **Nút ✕** để chủ động tắt thông báo.
- Biểu tượng ở thanh tác vụ đồng bộ sang hình khiên (trước đó còn là logo Electron).
- Rút ngắn dòng chữ hiện khi thu vào khay cho vừa khung.

---

## 3.3.1 — Bấm vào thông báo thì mở được app

Bấm vào toast không có gì xảy ra — do **ba nguyên nhân chồng lên nhau**, phải vá cả ba:

- **Đối tượng `Notification` bị bộ dọn rác thu mất.** Nó là biến cục bộ, `show()` xong là
  không còn ai tham chiếu, thu luôn cả trình xử lý `click` — toast vẫn hiện nhưng bấm vào
  chẳng gọi được gì. Nay giữ trong một `Set` cho tới khi đóng (chốt chặn 60 giây).
  *(Đo được: không giữ tham chiếu → `WeakRef.deref()` trả về `undefined`; có giữ → còn sống.)*
- **Windows chặn tiến trình nền cướp tiêu điểm**, nên `win.focus()` trơ một mình không kéo
  cửa sổ ra trước. Nay hiện ra → ghim tạm lên trên cùng → nhả ra + `app.focus({steal:true})`.
  *(Đo được: từ trạng thái ẩn → `isVisible: true, isFocused: true`.)*
- **Bản portable không có lối tắt trong Start Menu.** Windows chỉ chuyển cú bấm vào toast
  trở lại cho app nếu tìm thấy một lối tắt mang đúng AppUserModelID đó; bản cài NSIS tự tạo,
  bản portable thì không có gì để Windows gọi. Nay app tự tạo một lối tắt trong Start Menu
  của chính người dùng (không cần quyền quản trị, chỉ tạo khi chưa có).
- Bấm **một lần** vào biểu tượng khay cũng mở cửa sổ, không bắt phải bấm đúp.

## 3.3.0 — Thông báo kín đáo, menu khay gọn lại

- **Thông báo không còn lộ nội dung.** Toast của Windows hiện trên màn hình khóa và được
  lưu vào trung tâm thông báo — ai ngồi cạnh máy cũng đọc được. Một app nhắn tin mã hóa
  đầu cuối mà để tên người gửi và nội dung tin rò ra ở đó thì hỏng cả ý nghĩa. Nay chỉ hiện
  tiêu đề: *"Tin nhắn mới"*, *"Thiết bị mới xin kết nối"*, *"Thiết bị mới kết nối"*.
  Móc `onNotify(loại)` ở node cũng **chỉ truyền loại sự kiện** — tên và nội dung không bao
  giờ rời khỏi node, nên không có đường nào rò được.
- **Báo cả khi có thiết bị kết nối**, không chỉ khi có tin nhắn: lúc ai đó xin kết nối
  (cần bạn duyệt) và lúc bắt tay xong.
- **Menu khay rút còn ba mục**: *Mở* · *Thông báo* (bật/tắt) · *Thoát*.

## 3.2.0 — Khay hệ thống, thông báo Windows, và sửa mã QR tiếng Việt

- **Mã QR chứa tiếng Việt từng tạo ra chuỗi RỖNG.** `qrcode.js` mặc định dùng bộ mã
  `default`, nó cắt mất mọi ký tự ngoài ASCII — nên mã QR của điện thoại (tên
  *"Điện thoại d85b"*) quét ra vẫn là mã hợp lệ nhưng nội dung trống, máy tính không
  tài nào ghim được khóa. Mã của máy tính thoát nạn chỉ vì tên đã được
  `encodeURIComponent` thành ASCII. Nay cả hai trang đều dùng
  `qrcode.stringToBytesFuncs["UTF-8"]`. *(Đo được: trước khi vá giải ra rỗng ở MỌI kích
  thước, kể cả 530px; sau khi vá khớp nguyên văn.)*
- Mã QR của điện thoại vẽ ở ô 6px thay vì 4px, và có thêm **💾 Tải ảnh QR về** +
  **📋 Chép chuỗi khóa** — máy tính đọc mã này bằng cách tải ảnh, mà ảnh chụp màn hình
  điện thoại hay bị thu nhỏ dưới ngưỡng đọc được.
- **Biểu tượng khay hệ thống.** Bấm ✕ chỉ thu cửa sổ về khay (app vẫn nhận tin nhắn);
  muốn tắt hẳn thì chuột phải vào biểu tượng khiên → *Thoát Sentinell*. Menu khay gồm:
  mở cửa sổ, hiện mã QR ghép đôi, chép địa chỉ máy, bật/tắt thông báo, thoát.
- **Thông báo Windows khi có tin nhắn mới** — nhưng CHỈ khi người dùng không nhìn cửa sổ
  (cửa sổ bị che, thu nhỏ, hoặc đang chạy ngầm trong khay). Đang mở và focus thì im lặng.
  Bấm vào thông báo là mở lại cửa sổ.
- Icon khiên tự sinh bằng script (`scripts/gen-icon.mjs`) — 32/64/256px, không thêm
  phụ thuộc nào chỉ vì một cái icon.
- Gộp hai thông báo chồng nhau lúc ghim khóa thành một câu nói rõ bước tiếp theo.

## 3.1.1 — Vuốt xóa không còn tự bật về chỗ cũ

- **Vuốt xong hàng lại trượt về vị trí cũ.** Sau một cú vuốt, trình duyệt vẫn phát ra một
  sự kiện `click`; trình xử lý click lại xét trạng thái "đang mở" TRƯỚC cờ "vừa kéo xong",
  nên chính cú click ảo đó đóng hàng lại ngay lập tức. Đổi thứ tự là xong.
  *(Bản 3.1.0 đã kiểm bằng `PointerEvent` tự tạo — mà sự kiện tự tạo KHÔNG sinh ra cú click
  đi kèm như thao tác thật, nên lỗi lọt lưới. Nay kiểm bằng kéo chuột thật.)*
- Cử chỉ vuốt nghe `pointermove`/`pointerup` trên **window** thay vì trên chính hàng —
  khi hàng trượt sang trái, con trỏ dễ rơi ra ngoài nó (hoặc đè lên nút Xóa) làm đứt cử chỉ.
- Chặn kéo-thả và bôi đen mặc định của trình duyệt trong lúc vuốt (`preventDefault`,
  `user-select: none`), tránh bị cướp con trỏ giữa chừng.
- Đóng gói: `dist-retry.mjs` tự dò đường dẫn `electron-builder` (chạy script trực tiếp
  không còn lỗi *is not recognized*), in **nguyên văn** lỗi thay vì đổ tại "EPERM do Defender",
  và tự lùi về chế độ không cần mạng khi không tải được công cụ từ GitHub.

## 3.1.0 — Xóa cuộc trò chuyện, menu chuột phải, và dứt điểm tiến trình "ma"

- **Vuốt hàng trò chuyện sang trái** để lộ nút **Xóa** đỏ (kéo chuột trên máy tính cũng được).
  Xóa toàn bộ tin nhắn đã lưu và bỏ ghim khóa, có hỏi lại trước khi làm.
- **Menu chuột phải** trong Electron — trước đây bấm chuột phải không ra gì, mất cả
  Cắt/Chép/Dán, Chọn tất cả, chép liên kết, lưu ảnh.
- **Bỏ thông báo trùng.** Xác thực thất bại / bị từ chối / xóa cuộc trò chuyện từng hiện
  hai dòng chồng nhau, vì vừa gửi thông báo riêng vừa kèm lý do vào lệnh dọn phiên.
- **Không còn tiến trình "ma" giữ cổng.** `server.close()` chờ mọi kết nối đóng, mà
  WebSocket `/ui` thì không bao giờ tự đóng ⇒ `stop()` treo vĩnh viễn, `app.quit()` không
  tới lượt, tiến trình sống tiếp và giữ cổng. Lần mở sau rơi sang cổng khác, còn mã QR cũ
  trỏ vào "xác" đó nên hoặc treo, hoặc trả về đúng một dòng `Cannot GET /join`.
  Nay ngắt thẳng mọi socket, có hạn giờ 1,5 giây, và Electron ép thoát sau 3 giây.
  *(Đo được: cách cũ 4 giây vẫn chưa trả về; cách mới 13 ms.)*
- **Chọn đúng card mạng.** `localIp()` từng lấy card IPv4 đầu tiên bất kỳ — máy có
  VirtualBox/WSL/VPN là mã QR mang địa chỉ điện thoại không với tới được, trang cứ xoay mãi.
  Nay chấm điểm theo tên card và dải địa chỉ; máy nhiều card thì cửa sổ QR có **ô chọn địa chỉ**.
- **Nói rõ vì sao không gọi lại được điện thoại.** Điện thoại vào bằng trang `/join` là một
  trang web, không mở cổng nào nên không nhận cuộc gọi đến. Trước đây ta đoán bừa cổng 8000
  rồi đâm vào `ECONNREFUSED`; nay báo phải để thiết bị đó chủ động quét và bấm Kết nối.
- Đóng gói xong tự **xóa mọi `.exe` sai phiên bản** còn sót trong `release/`.

## 3.0.0 — Giao diện app nhắn tin

Viết lại toàn bộ giao diện web/desktop theo quy ước của các app nhắn tin thật.

- **Bố cục bốn cột**: thanh biểu tượng (Trò chuyện · LAN · Khóa · Nhật ký · Nền) →
  danh sách trò chuyện → phòng chat → bảng bảo mật bật/tắt.
- **Danh sách trò chuyện thật**: avatar (chữ cái từ tên, màu sinh từ vân tay khóa),
  tin nhắn cuối, giờ, sắp theo thời gian. Thêm `Storage.lastMessage()` ở phía node.
- **Bong bóng đúng chuẩn**: bo tròn, gom cụm tin cùng người gửi trong 5 phút,
  vạch ngăn theo ngày, chỉ hiện giờ thay vì nhãn kỹ thuật trên từng tin.
- **Hai chế độ màu** sáng/tối, có nút chuyển, nhớ lựa chọn, mặc định theo hệ thống.
- **Bảng bảo mật** hiện safety number và nhật ký giao thức ngay cạnh khung chat.
- Dưới 900px tự gập thành một cột, thanh biểu tượng chuyển xuống thành tab đáy.
- Trang `/join` của điện thoại dùng chung hệ màu và bong bóng mới.
- **Cuộn theo từng cột** thay vì cuộn cả trang; thanh cuộn mảnh, nền trong suốt,
  chỉ hiện khi rê chuột, có hai mũi tên.

## 2.3.2 — Đóng cửa sổ và phản hồi cho điện thoại

- Cửa sổ quét QR tự đóng ở **mọi** đường vào (camera, tải ảnh, dán chuỗi) — trước đó
  chỉ đường camera mới đóng. Đọc thất bại thì cố ý giữ cửa sổ để thử lại ngay.
- Hộp duyệt kết nối tự gỡ khi bên xin kết nối biến mất giữa chừng.
- Trang `/join`: thông báo từng bị ghi vào khung chat đang ẩn nên **không ai nhìn thấy**.
  Nay có băng trạng thái to rõ cho bận / bị từ chối / chờ duyệt / không kết nối được,
  kèm nút *Thử kết nối lại*. Rớt giữa chừng thì quay về sảnh thay vì kẹt ở khung chat chết.
- Máy tính được báo khi vừa từ chối ai đó vì đang bận.

## 2.3.1 — Sửa bẫy kẹt cửa sổ

- `closeKeyModal()` và `noteConnectedInModal()` bị gọi mà **chưa từng được định nghĩa** →
  bấm ✕ ném lỗi, cửa sổ QR không đóng được, lại che mất hộp duyệt kết nối khiến máy kia
  treo ở "đang kết nối" tới khi hết 60 giây.
- Hộp duyệt nâng lên `z-index: 70` để không bị cửa sổ QR che.
- Thêm khung `{type:"pending"}` báo cho bên gọi biết đang chờ người kia bấm Chấp nhận.
- Bỏ liên kết mời bị in hai lần trong cửa sổ QR.
- Esc / bấm ra nền đóng được mọi cửa sổ (trừ hộp duyệt — cố ý bắt chọn có ý thức).

## 2.3.0 — Một mã QR duy nhất

- Gộp hai mã QR thành **một** URL `/join#k=&n=&pc=` mang sẵn cả địa chỉ, nên bên kia
  đọc mã xong là ghim khóa và **vào chat luôn**.
- Thêm **Tải ảnh QR về** (PNG 570px) và **Chép liên kết** — bỏ hẳn việc bắt người dùng
  chụp màn hình mã QR, thứ gần như luôn thất bại vì ảnh bị thu nhỏ.
- `parseQr()` chuyển vào `core/protocol.js` dùng chung cho mọi nền tảng.
- Bọc `jsQR` trong try/catch: nó có thể **ném lỗi** chứ không chỉ trả về rỗng.
- Nhật ký giao thức chặn ở 150 dòng và không còn tràn viền.

## 2.2.0 — Kiểm soát kết nối đến

- Thiết bị lạ phải qua hộp **duyệt** (tự từ chối sau 60 giây), khóa đã ghim thì vào thẳng.
- **Chế độ chặt**: chỉ nhận kết nối từ liên hệ đã ghim khóa, người lạ bị chặn kèm lý do.
- Giữ lại chữ ký đến sớm (`_deferredSig`) và xử lý lại sau khi người dùng bấm duyệt.

## 2.1.0 — Ghép đôi hai chiều

- QR mang **mã ghép đôi dùng một lần** dạng 3 từ; bên quét gửi
  `pair_proof = HMAC-SHA256(mã, SHA-256(transcript))` nên **hai bên cùng ghim khóa nhau**
  chỉ với một lần quét.
- Handshake khai báo cổng đang lắng nghe → danh bạ đủ địa chỉ để bên nào cũng mở lại
  cuộc trò chuyện được ("Nhắn lại").
- Nhịp tim ping/pong 15 giây: phiên chết không còn làm kẹt "đang bận" vĩnh viễn.
- `/api/info` trả cổng **đã bind** thay vì cổng yêu cầu.

## 2.0.0 — Kiến trúc node

Bỏ mô hình "một host + hai trình duyệt khách" vì nó vẫn còn một máy đứng giữa.

- Mỗi thiết bị chạy **node riêng**, nối thẳng với nhau — không có bên thứ ba.
- Một lõi mật mã JavaScript (`core/protocol.js`) chạy trên Node.js, Electron,
  trình duyệt và React Native; đối chiếu với bản Python bằng vector kiểm thử chéo.
- Desktop đóng gói bằng Electron + electron-builder (NSIS và portable).
- Tìm thiết bị trên LAN qua mDNS (`_sentinell._tcp`).
- Lưu cục bộ: khóa bọc bằng `safeStorage` (DPAPI), lịch sử trong SQLite mã hóa AES-256-GCM.
- App mobile Expo (Android + iOS) dùng chung lõi.

## 1.0.0 — Bản Python đầu tiên

- Host FastAPI phục vụ giao diện web, hai trình duyệt chat qua relay WebSocket.
- ECDHE P-256 + ECDSA + HKDF + AES-256-GCM + ratchet mỗi tin + safety number.
- Trang demo thuật toán (DH, RSA, mã cổ điển, hàm băm) và chế độ demo tấn công MITM.
- Còn giữ trong `reference/python/` làm bản đối chiếu cho kiểm thử liên ngôn ngữ.
