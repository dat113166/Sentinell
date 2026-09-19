# 🛡️ Sentinell — Nhắn tin bảo mật đầu cuối P2P giữa các thiết bị trên LAN

> **Phiên bản 3.6.0** — xem [CHANGELOG.md](CHANGELOG.md) để biết từng bản đã đổi gì.

Ứng dụng nhắn tin **mã hóa đầu cuối (E2EE)** theo mô hình **ngang hàng (P2P)**: mỗi thiết bị
là một *node* độc lập, tự tìm thấy nhau trên LAN/hotspot, trao đổi khóa qua QR và nhắn tin
trực tiếp — **không có máy chủ trung gian nào đọc được nội dung**. Đồ án môn *An toàn và
Bảo mật thông tin*.

**Một lõi giao thức (JavaScript) — nhiều nền tảng:**

| Nền tảng | Trạng thái | Cách dùng |
|---|---|---|
| 💻 **PC (Windows)** — app Electron, có `.exe` | ✅ | `npm run desktop` hoặc chạy `Sentinell.exe` |
| 📱 **Điện thoại qua trình duyệt** (không cài app) | ✅ | Quét QR trên PC → mở trang `/join` |
| 📱 **Android** — app đầy đủ (APK) | ✅ | Cài `Sentinell-android-<phiên bản>.apk` — tự nghe kết nối, tìm LAN, mật khẩu |
| 📱 **iPhone** — qua Expo Go | ✅ | `npm run mobile` → quét QR bằng **Expo Go** (không cần Mac; chỉ gọi đi được) |
| 🐍 **Python** — bản tham chiếu + test vector | ✅ | `reference/python/` — vẫn là peer hợp lệ |

## Đáp ứng 5 tiêu chí đề bài

| # | Tiêu chí | Cách Sentinell đáp ứng |
|---|---|---|
| 1 | **Lưu trữ cục bộ** | Khóa trong `identity.json` (khóa bí mật bọc bằng **DPAPI/Keychain** qua Electron `safeStorage`); tin nhắn trong SQLite **mã hóa at-rest** AES-256-GCM. |
| 2 | **Quản lý khóa (tạo, đổi)** | Tự sinh ECDSA P-256; **xoay khóa** (giữ khóa cũ, lịch sử vẫn đọc được); **sao lưu / phục hồi**; ghim khóa liên hệ. |
| 3 | **Nhắn tin mã hóa** | ECDHE + chữ ký ECDSA + HKDF + AES-256-GCM + ratchet mỗi tin (forward secrecy). Văn bản + file/ảnh. |
| 4 | **Tìm kiếm trên LAN** | mDNS/DNS-SD (`_sentinell._tcp`) — node tự quảng bá & phát hiện nhau, không gõ IP. |
| 5 | **Trao đổi khóa qua QR** | PC↔PC: quét QR khóa công khai (camera tại `localhost`). PC↔điện thoại: QR chứa **URL + khóa PC**, quét bằng camera hệ thống → tự ghim, chống mạo danh. |

Chi tiết lý thuyết và ánh xạ tài liệu: [docs/BAOCAO.md](docs/BAOCAO.md).

---

## Kiến trúc

```
core/protocol.js            Lõi giao thức (JS, @noble) — dùng chung mọi nền tảng
├─ desktop/  (Electron)     Node.js: mDNS (bonjour-service) + WebSocket /peer + SQLite + safeStorage
│                           Renderer: giao diện web/  →  Sentinell.exe
├─ web/      (UI chung)     index.html (UI app) · join.html (điện thoại qua web) · demos/
├─ mobile/   (Expo RN)      Android/iOS: camera quét QR, SecureStore (Keychain/Keystore), SQLite
└─ reference/python/        Bản tham chiếu Python; scripts/ kiểm chứng interop Python↔JS
```

- **Node là đầu cuối thật**: mật mã chạy trong tiến trình của từng thiết bị; dữ liệu rời máy
  đã là bản mã. Giữa hai node không có ai ở giữa.
- **Điện thoại qua web ("chế độ Lai")**: PC hiện QR `http://<ip>:<port>/join#k=<khóa PC>`;
  điện thoại quét bằng camera hệ thống → trang `/join` chạy **cùng lõi giao thức trong
  trình duyệt**, ghim khóa PC lấy từ QR (out-of-band), rồi bắt tay thẳng với `/peer` của PC.
  PC **không giữ khóa của điện thoại**. Giao diện PC mở ở `localhost` nên camera quét QR của
  điện thoại (để ghim ngược) cũng hoạt động.

## Cài đặt

Yêu cầu **Node.js 20+**. Tại thư mục gốc:

```bash
npm install
```

(Python 3.10+ chỉ cần nếu muốn chạy bản tham chiếu / test interop: `pip install -r reference/python/requirements.txt`.)

## Chạy

**App desktop (Electron):**

```bash
npm run desktop
```

**Thử 2 thiết bị trên 1 máy** (hai node, hai cổng, hai kho dữ liệu):

```bash
npm --workspace desktop run node -- --port 8000 --data ./data-a
```

```bash
npm --workspace desktop run node -- --port 8001 --data ./data-b
```

rồi mở `http://127.0.0.1:8000/` và `http://127.0.0.1:8001/`. (Electron cũng nhận `--port`/`--data`:
`npm run desktop -- --port 8001 --data ./data-b`.)

**Đóng gói `.exe`** (NSIS installer + bản portable, xuất ra `desktop/release/`):

```bash
npm run desktop:build
```

### Gửi bản `.exe` cho người khác

`Sentinell-portable-<phiên bản>.exe` (~113 MB) là **một file tự chứa** — máy nhận **không cần cài
Python, Node.js** hay bất cứ thứ gì. Chỉ cần chép file và chạy. Bốn điều nên dặn trước:

| Điều họ sẽ gặp | Cách xử lý |
|---|---|
| **SmartScreen**: “Windows protected your PC” | File **chưa ký số** → bấm *More info → Run anyway*. Muốn hết cảnh báo phải mua chứng chỉ ký code. |
| **Tường lửa Windows hỏi quyền mạng** | **Bắt buộc bấm Allow**, và nhớ tick **cả “Private networks”** (WiFi nhà thường là Private) — không cho thì hai máy không thấy nhau. |
| **Máy kia cũng cần app** để chat PC↔PC | Hoặc họ dùng **điện thoại quét mã QR** → vào chat bằng trình duyệt, không cần cài gì. |
| **Chỉ chạy trên Windows x64** | macOS/Linux phải build riêng trên đúng hệ đó. |

Dữ liệu (khóa, tin nhắn) lưu ở `%APPDATA%\sentinell-desktop\` — **không** nằm cạnh file exe.
Xóa exe thì tài khoản vẫn còn; muốn xóa sạch phải xóa thư mục đó.

Nếu cổng 8000 trên máy họ đã bị chiếm, app **tự chuyển sang cổng trống kế tiếp** (8001…8019);
trường hợp không còn cổng nào, app hiện hộp thoại báo lỗi thay vì thoát im lặng.

## Giao diện

Bố cục như một app nhắn tin: **thanh biểu tượng** bên trái → **danh sách trò chuyện** →
**phòng chat** → **bảng bảo mật** bật/tắt bằng nút 🛡.

| Biểu tượng | Nội dung |
|---|---|
| 💬 Trò chuyện | danh sách cuộc trò chuyện: avatar, tin nhắn cuối, giờ |
| 📡 LAN | thiết bị tự tìm thấy qua mDNS (có chấm báo khi xuất hiện máy mới) |
| 🔑 Khóa | danh tính, mã QR, ghim khóa, chế độ chặt, sao lưu / xoay khóa |
| 📜 Nhật ký | mọi thông báo kết nối, ghép đôi và lỗi |
| 🌙 Nền | chuyển nền sáng ↔ tối (mặc định theo hệ thống, nhớ lựa chọn) |

Bảng 🛡 hiện **safety number** và **nhật ký giao thức** ngay cạnh khung chat — thấy được
mật mã đang chạy trong lúc nhắn tin.

Màn hẹp dưới 900px (điện thoại, cửa sổ nhỏ) tự gập thành **một cột**: thanh biểu tượng
chuyển xuống thành tab đáy, mở một cuộc trò chuyện thì phòng chat chiếm hết màn kèm nút quay lại.

## Cách dùng

1. Mở Sentinell trên hai máy cùng WiFi/hotspot → tab **📡 LAN** tự hiện nhau.
2. Máy A vào tab **🔑 Khóa** → **Hiện khóa & mã QR** → **một mã duy nhất** dùng cho mọi thiết bị.
3. Máy B đọc mã đó, chọn cách nào tiện:
   - **điện thoại**: quét bằng camera thường → mở thẳng trang chat;
   - **máy tính**: A bấm **💾 Tải ảnh QR về** hoặc **📋 Chép liên kết**, gửi sang B,
     B vào **📷 Quét QR** → *Tải ảnh QR* (hoặc dán chuỗi).
4. Máy A bấm **Chấp nhận** ở hộp *"Có thiết bị muốn nhắn tin"* → vào chat ngay,
   huy hiệu *"đã xác minh (ghim QR) ✓"*, safety number khớp.
5. Nhắn tin, gửi file/ảnh. Lịch sử lưu mã hóa trên máy, tự nạp lại khi kết nối lại.

> Mã đã kèm sẵn địa chỉ máy A, nên B đọc xong là **ghim khóa và kết nối luôn** — không phải
> đi tìm nút Kết nối. Đừng **chụp màn hình** mã QR: ảnh chụp hay bị thu nhỏ nên máy kia đọc
> không ra; dùng nút *Tải ảnh QR về* hoặc *Chép liên kết*.

**Ai được phép kết nối vào?** Khóa lạ luôn phải qua hộp duyệt (tự từ chối sau 60s). Tick
**"Chỉ nhận kết nối từ liên hệ đã ghim khóa"** thì người lạ bị chặn thẳng, khỏi hỏi.

## Chạy ngầm trong khay hệ thống

Bấm **✕** chỉ **thu cửa sổ về khay** — app vẫn chạy và vẫn nhận tin nhắn, giống Zalo/Telegram.
Chuột phải vào biểu tượng khiên ở khay để: mở lại cửa sổ, hiện mã QR ghép đôi, chép địa chỉ
máy, bật/tắt thông báo, hoặc **Thoát Sentinell** (đây mới là cách tắt hẳn).

**Thông báo** hiện dưới dạng toast của Windows khi có **tin nhắn mới** hoặc **thiết bị mới
kết nối**, nhưng **chỉ khi bạn không đang nhìn cửa sổ** — cửa sổ bị che, thu nhỏ, hoặc app
đang chạy ngầm. Đang mở và focus thì không làm phiền. Bấm vào thông báo là mở lại cửa sổ.

> Thông báo **cố ý không hiện tên người gửi hay nội dung tin**, chỉ hiện tiêu đề kiểu
> *"Tin nhắn mới"*. Toast nằm trên màn hình khóa và được lưu vào trung tâm thông báo của
> Windows — để nội dung rò ra ở đó thì mã hóa đầu cuối còn ý nghĩa gì. Ở tầng node, móc
> thông báo cũng chỉ nhận **loại sự kiện**, không nhận tên lẫn nội dung.

## Xóa một cuộc trò chuyện

**Vuốt hàng trò chuyện sang trái** (trên máy tính thì kéo bằng chuột) → hiện nút **Xóa** đỏ.
Xóa sẽ bỏ toàn bộ tin nhắn đã lưu **trên máy này** và bỏ ghim khóa của liên hệ đó — muốn nhắn
lại thì phải quét QR một lần nữa. Tin nhắn ở máy bên kia không bị ảnh hưởng.

## Điện thoại dùng trình duyệt thì KHÔNG nhận được cuộc gọi đến

Trang `/join` chỉ là một trang web trong trình duyệt — nó không mở cổng nào, nên máy tính
**không thể chủ động gọi sang**. Muốn nhắn lại: để điện thoại mở mã QR của máy tính rồi bấm
*Kết nối*. Máy tính ↔ máy tính thì bên nào gọi trước cũng được, vì cả hai đều tự lắng nghe.

App Android (bản APK) thì khác: nó **tự lắng nghe** (cổng 8000), nên máy tính và điện thoại
khác gọi sang bình thường — QR của điện thoại mang kèm địa chỉ, máy tính quét là gọi sang luôn.

## Ghép đôi: quét MỘT lần, hai bên nhớ nhau

QR mang theo một **mã ghép đôi dùng một lần** (dạng 3 từ, ví dụ `gau-mong-nau`). Bên quét gửi
kèm một *bằng chứng* HMAC gắn với đúng phiên đó, nên bên hiện QR **tự ghim khóa của bên quét**.

Chỉ cần **một bên quét một lần**:
- Cả hai cùng lưu nhau vào **Đã ghim qua QR**, kèm địa chỉ gặp gần nhất.
- **Bên nào cũng bấm “Nhắn lại” được** để mở lại cuộc trò chuyện cũ — không phải quét ngược.
- Mã tự đổi sau khi dùng; bằng chứng gắn với transcript nên kẻ nghe lén **không tái dùng được**.

Không quét được camera? Đọc **mã 3 từ** cho nhau, hoặc dán chuỗi khóa / tải ảnh QR.

Địa chỉ LAN của máy hiện sẵn ở tab **🔑 Khóa** kèm nút chép, để gõ nhanh vào ô “Kết nối thủ công”
(trong tab **📡 LAN**) của thiết bị kia khi mạng chặn QR.

Máy có nhiều card mạng (VirtualBox, WSL, VPN) thì cửa sổ QR có thêm **ô chọn địa chỉ** — đổi sang
card khác nếu điện thoại quét xong mà trang cứ xoay không tải.

## Kiểm chứng interop (Python ↔ JavaScript)

Bản Python tham chiếu và lõi JS phải cho **cùng kết quả** với cùng đầu vào — đây là bằng chứng
giao thức được đặc tả chặt, không phụ thuộc ngôn ngữ:

```bash
npm run test:vectors
```

(sinh vector bằng Python → JS kiểm chứng transcript/khóa dẫn xuất/safety number, xác minh chữ
ký DER của Python và giải mã bản mã của Python → Python xác minh & giải mã ngược lại.)
Ngoài ra node Python (`python reference/python/app.py --port 8003`) **hiện lên trong danh sách
LAN và chat được** với node Electron.

## Nơi lưu dữ liệu

Electron: `%APPDATA%\sentinell-desktop\sentinell-data\` (hoặc thư mục `--data`):
`identity.json` (khóa bí mật đã bọc DPAPI), `contacts.json`, `messages.db` (mã hóa at-rest), `files/`.

## Kiểm chứng bằng Wireshark

Bắt gói giữa hai máy, filter theo cổng node; khung WebSocket `/peer` chỉ là **hex bản mã** (`ct`).

## App Android đầy đủ (APK)

Bản build thật (không phải Expo Go) là một **node đầy đủ** như máy tính: tự nghe kết nối (máy chủ
WebSocket tự viết, `mobile/src/wsproto.js`), tìm máy trong LAN bằng mDNS, khóa bí mật bọc bằng
mật khẩu (scrypt native), rời app quá 5 phút thì tự khóa. Có sẵn APK thì chỉ cần chép sang điện
thoại và cài (cho phép "cài ứng dụng không rõ nguồn gốc").

Tự build APK trên Windows (cần Android Studio + SDK, và **JDK 17** — JDK 25 đi kèm Android Studio
làm bước CMake của Gradle hỏng):

```powershell
cd mobile
npx expo prebuild --platform android      # sinh mobile/android/ từ app.json (không commit thư mục này)
$env:JAVA_HOME = "<đường dẫn JDK 17>"
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
cd android
.\gradlew.bat assembleRelease "-PreactNativeArchitectures=arm64-v8a,x86_64"
# → mobile\android\app\build\outputs\apk\release\app-release.apk
```

APK này ký bằng khóa debug: đủ để cài và demo, chưa đưa lên cửa hàng được.

Thử không cần điện thoại: máy ảo Android 16 (x86_64) trong Android Studio. Máy ảo nằm sau mạng
riêng nên từ trong đó máy tính là `10.0.2.2`; muốn máy tính gọi vào máy ảo thì
`adb forward tcp:8100 tcp:8000` rồi gọi `127.0.0.1:8100`. mDNS giữa máy ảo và LAN thật **không**
thông — phần đó phải thử bằng điện thoại thật.

## iPhone qua Expo Go

Chạy bằng **Expo Go** — không cần build, **không cần máy Mac**. Expo Go không có các mô-đun
native của bản Android (TCP, mDNS, scrypt native) nên ở đây điện thoại **chỉ gọi đi** được:

1. Cài **Expo Go** (Google Play / App Store) trên điện thoại.
2. Trên PC, cùng WiFi với điện thoại:

```bash
npm run mobile
```

3. Quét mã QR hiện trong terminal: **Android** dùng chính app Expo Go; **iPhone** dùng app
   Camera rồi mở bằng Expo Go.

> **iPhone báo “You need to be signed in to Expo Go and Expo CLI”?**
> Đây **không phải lỗi của app** — từ SDK 57, Expo Go **trên iOS** bắt buộc đăng nhập ở **cả hai
> đầu** bằng **cùng một tài khoản Expo** (tài khoản miễn phí). Cách xử lý:
> 1. Trên PC: `npx expo login`
> 2. Trong app Expo Go: tab **Home** → chạm **avatar góc trên phải** → đăng nhập cùng tài khoản đó
> 3. Quét lại QR.
>
> Yêu cầu này **chưa áp dụng cho Android** (Expo Go Android chạy được ngay, không cần đăng nhập)
> và **không áp dụng** cho development build hay máy giả lập.
4. Trong app: bấm **“Mở camera quét QR”**, quét mã *“Mời điện thoại”* trên màn hình PC
   (mục 🔑 Khóa & QR của tôi) → điện thoại tự ghim khóa PC và bắt tay mã hóa.

Điện thoại là **đầu cuối thật**: khóa nằm trong Keychain (iOS) / Keystore (Android) qua
`expo-secure-store`, lịch sử tin nhắn trong SQLite **mã hóa at-rest**, mã hóa/giải mã chạy
ngay trên máy bằng cùng `core/protocol.js`.

Muốn xem/thử app mobile mà không có điện thoại (tiện khi demo trên máy chiếu):

```bash
npm run mobile:web
```

chạy chính app đó trong trình duyệt (camera không dùng được — hãy dùng “Kết nối thủ công”).

**Giới hạn:** trong Expo Go điện thoại chỉ **kết nối ra** một node đang lắng nghe (PC, hoặc
điện thoại Android bản APK). iOS ngoài Expo Go cần tài khoản Apple Developer hoặc máy Mac.

## Lưu ý

- Đồ án học tập: giao thức là bản rút gọn theo bài giảng, không thay thế ứng dụng đã kiểm định.
- mDNS cần cùng mạng L2; nếu mạng chặn multicast, dùng **Kết nối thủ công (IP:cổng)**.
- Chạy hai bản trên cùng máy để thử → dùng `--data` khác nhau để tách kho khóa/tin nhắn.
