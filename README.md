# 🛡️ Sentinell — Nhắn tin mã hóa đầu cuối, ngang hàng, không máy chủ

> **Phiên bản 3.17.0** · [Tải về (Releases)](https://github.com/dat113166/Sentinell/releases/latest) ·
> [Báo cáo đồ án](docs/BAOCAO.md) · [Lịch sử thay đổi](CHANGELOG.md)

Đồ án môn *An toàn và Bảo mật thông tin* (ĐH Hồng Đức): hai **ứng dụng cài trên máy** — app
**Windows** và app **Android** — nhắn tin **mã hóa đầu cuối (E2EE)** trực tiếp với nhau theo mô
hình **ngang hàng (P2P)**. Không có máy chủ trung tâm, không có đám mây: mỗi thiết bị tự sinh và
**tự giữ khóa bí mật của mình**, tự tìm nhau trong mạng LAN, trao đổi khóa qua QR, rồi nói chuyện
thẳng với nhau.

## Mô hình ngang hàng

```
   ┌──────────────┐            ┌──────────────┐            ┌──────────────┐
   │ App Windows  │◄──────────►│ App Android  │◄──────────►│ App Android  │
   │  (.exe)      │  E2EE P2P  │  (.apk)      │  E2EE P2P  │  (.apk)      │
   │ khóa: DPAPI  │            │ khóa:Keystore│            │ khóa:Keystore│
   └──────▲───────┘            └──────────────┘            └──────────────┘
          │                 mọi cặp thiết bị đều nói chuyện TRỰC TIẾP
          ▼
   ┌──────────────┐
   │ App Windows  │     Không có máy chủ trung gian · không có đám mây ·
   └──────────────┘     hai điện thoại nhắn nhau KHÔNG cần máy tính
```

- **Mỗi thiết bị là một nút ngang hàng (node):** vừa **nhận** kết nối vừa **gọi** đi — giống
  BitTorrent. "Nhận kết nối" không biến thiết bị thành máy chủ trung tâm: không ai đứng giữa,
  không ai giữ tin nhắn hay khóa của người khác.
- **Khóa bí mật không bao giờ rời thiết bị.** Windows: bọc bằng DPAPI (`safeStorage`). Android:
  Keystore (`expo-secure-store`). Cả hai có thể **bọc thêm bằng mật khẩu** (scrypt → AES-256-GCM).
- **Nối thẳng không qua router:** một điện thoại bật **điểm phát sóng**, máy kia vào thẳng — giữa
  hai máy không còn thiết bị nào khác. Dùng chung WiFi cũng được (router chỉ chuyển gói bản mã).
- **Dữ liệu rời máy đã là bản mã:** ECDH P-256 tạm thời + chữ ký ECDSA + HKDF + AES-256-GCM, đổi
  khóa sau **mỗi** tin (forward secrecy). Wireshark chỉ thấy hex bản mã.

## Hai ứng dụng

| | 💻 **App Windows** | 📱 **App Android** |
|---|---|---|
| Cài đặt | `Sentinell-portable-3.17.0.exe` (chạy luôn) hoặc bản Setup | `Sentinell-android-3.17.0.apk` (Android 7+) |
| Công nghệ | Electron + Node.js | React Native: giao diện Android thật (không phải trang web nhúng) + mô-đun native (TCP, NSD, Keystore, OpenSSL) |
| Nhận kết nối | ✅ cổng 8000 (tự dời nếu bận) | ✅ cổng 8000 — máy chủ WebSocket tự viết theo RFC 6455 |
| Tìm nhau trong LAN | ✅ mDNS `_sentinell._tcp` | ✅ mDNS qua NsdManager của Android |
| Giữ khóa bí mật | DPAPI + mật khẩu tùy chọn (scrypt N=2¹⁷) | Keystore + mật khẩu tùy chọn (scrypt native N=2¹⁷, tự khóa sau 5 phút rời app) |
| Lịch sử | SQLite, **mã hóa at-rest** | SQLite, **mã hóa at-rest** |
| QR | Hiện + quét (camera hoặc ảnh) | Hiện + quét bằng camera |
| Gửi tệp/ảnh | ✅ mọi loại tệp (tối đa 200 MB) | ✅ gửi ảnh · nhận mọi loại tệp |

Cả hai chạy **cùng một lõi giao thức** `core/protocol.js` (thư viện mật mã đã kiểm định `@noble`),
nên nói chuyện được với nhau theo mọi chiều.

### Các cặp kết nối đã kiểm

| Kết nối | Kết quả |
|---|---|
| Windows ↔ Windows | ✅ giữa các node: app Electron, bản `.exe` đóng gói, node Node.js (và node Python tham chiếu) |
| Android → Windows (điện thoại gọi) | ✅ máy ảo Android 16 ↔ node Windows |
| Windows → Android (máy tính gọi, điện thoại nhận) | ✅ máy ảo Android 16: hộp duyệt → nhắn hai chiều |
| Android ↔ Android | ✅ bài kiểm tự động — cả hai đầu là mã của app, không có máy tính (`npm run test:phone`) · ⏳ **chưa quay trên hai điện thoại thật** |
| Tìm nhau bằng mDNS | ✅ Windows ↔ Windows ↔ Python · Android: đăng ký/dò/phân giải chạy (máy ảo thấy chính nó) · ⏳ hai điện thoại thật |

## Đáp ứng 5 tiêu chí đề bài

| # | Tiêu chí | Windows | Android |
|---|---|---|---|
| 1 | **Lưu trữ cục bộ** | `identity.json` bọc DPAPI; tin nhắn SQLite mã hóa AES-256-GCM | Khóa trong Keystore; tin nhắn SQLite mã hóa AES-256-GCM |
| 2 | **Quản lý khóa (tạo, đổi)** | Tự sinh ECDSA P-256; **xoay khóa** (lịch sử vẫn đọc được); sao lưu có mật khẩu; mật khẩu tài khoản | Tự sinh; **xoay khóa**; mật khẩu bọc khóa (đặt/đổi/bỏ) |
| 3 | **Nhắn tin mã hóa** | ECDHE + ECDSA + HKDF + AES-256-GCM + ratchet mỗi tin; chữ + tệp | Cùng giao thức; chữ + ảnh |
| 4 | **Tìm kiếm trên LAN** | mDNS tự quảng bá & phát hiện | mDNS (NsdManager) |
| 5 | **Trao đổi khóa qua QR** | QR mang khóa + địa chỉ + mã ghép đôi dùng một lần | Như Windows; quét xong là **ghim khóa và gọi sang luôn** |

Chống mạo danh: khóa đã ghim qua QR phải **khớp** chữ ký trong bắt tay, lệch là hủy. Khóa lạ phải
được **duyệt**; bật **chế độ chặt** thì chỉ nhận liên hệ đã ghim. Chi tiết lý thuyết và ánh xạ
tài liệu: [docs/BAOCAO.md](docs/BAOCAO.md).

---

## Dùng thử nhanh

Tải tệp ở trang [Releases](https://github.com/dat113166/Sentinell/releases/latest) và kiểm mã
băm SHA-256 ghi trên đó (`Get-FileHash <tệp> -Algorithm SHA256`).

**Hai điện thoại Android:**
1. Cài APK trên cả hai (cho phép *cài ứng dụng không rõ nguồn gốc*).
2. Điện thoại A bật **điểm phát sóng**, điện thoại B vào mạng đó (hoặc cả hai cùng một WiFi).
3. Mục **📡 Trong mạng LAN** tự hiện máy kia → bấm **Kết nối**. Hoặc B bấm **Mở camera quét QR**
   và quét mã ở mục **📱 Khóa của điện thoại này** trên A → ghim khóa và vào chat ngay.
4. A bấm **Chấp nhận** ở hộp *"Thiết bị lạ muốn kết nối"* → nhắn tin. Đối chiếu safety number
   nếu kết nối không qua QR.

**Windows ↔ Android / Windows ↔ Windows:** giống hệt — mở app, quét QR của máy kia (hoặc chọn
trong danh sách LAN), bên được gọi bấm *Chấp nhận*.

> Lần đầu mở app Windows, **tường lửa hỏi quyền mạng**: phải bấm *Allow* và tick **cả "Private
> networks"**, không thì hai máy không thấy nhau. File `.exe` chưa ký số nên SmartScreen cảnh
> báo → *More info → Run anyway*.

## Kiến trúc mã nguồn

```
core/protocol.js     Lõi giao thức (JS, @noble) — dùng chung cho mọi ứng dụng
desktop/             App Windows (Electron)
  server/            phần "node" chạy trong app: nhận kết nối P2P (/peer), mDNS, SQLite, khóa
                     (tên thư mục là "server" theo nghĩa socket nghe — KHÔNG phải máy chủ trung tâm)
web/                 Giao diện của app Windows (index.html) + trang phụ /join + demo thuật toán
mobile/              App Android (React Native / Expo)
  src/wsproto.js     máy chủ WebSocket RFC 6455 tự viết — để điện thoại NHẬN kết nối
  src/transport.js   phiên P2P, dùng cho cả gọi đi lẫn nhận vào
  src/discovery.js   mDNS · src/storage.js  Keystore + mật khẩu + SQLite mã hóa
reference/python/    Bản tham chiếu Python — kiểm interop (cùng kết quả với bản JS)
scripts/             8 bộ kiểm tra tự động (npm test)
```

## Cài đặt & build từ mã nguồn

Yêu cầu **Node.js 20+**. Tại thư mục gốc: `npm install`.

**App Windows:** `npm run desktop` (chạy thử) · `npm run desktop:build` (đóng gói `.exe` vào
`desktop/release/`). Thử hai node trên một máy:

```bash
npm --workspace desktop run node -- --port 8000 --data ./data-a
```

```bash
npm --workspace desktop run node -- --port 8001 --data ./data-b
```

rồi mở `http://127.0.0.1:8000/` và `http://127.0.0.1:8001/`.

**App Android** (cần Android Studio + SDK và **JDK 17** — JDK 25 đi kèm Android Studio làm bước
CMake của Gradle hỏng):

```powershell
cd mobile
npx expo prebuild --platform android      # sinh mobile/android/ từ app.json (không commit thư mục này)
$env:JAVA_HOME = "<đường dẫn JDK 17>"
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
cd android
.\gradlew.bat assembleRelease "-PreactNativeArchitectures=arm64-v8a,x86_64"
# → mobile\android\app\build\outputs\apk\release\app-release.apk
```

APK ký bằng khóa debug: đủ để cài và demo, chưa đưa lên cửa hàng được. Thử không cần điện thoại:
máy ảo Android trong Android Studio (từ trong máy ảo, máy tính là `10.0.2.2`; muốn máy tính gọi
vào máy ảo thì `adb forward tcp:8100 tcp:8000` rồi gọi `127.0.0.1:8100`). mDNS giữa máy ảo và
LAN thật không thông — phần đó phải thử bằng điện thoại thật.

## Kiểm chứng

```bash
npm test
```

Chạy 8 bộ kiểm: test vector chéo **Python ↔ JS** (hai cài đặt khác ngôn ngữ cho cùng transcript,
khóa dẫn xuất, safety number, và giải mã được của nhau), khung nhị phân, truyền tệp, tìm kiếm,
tài khoản/mật khẩu, bảo mật LAN, **máy chủ WebSocket của điện thoại** (chạy với chính thư viện
`ws` của app Windows), và **phiên P2P của điện thoại** (node Windows thật gọi vào điện thoại; hai
điện thoại nhắn thẳng; duyệt, ghép đôi hai chiều, chế độ chặt, bận, phát hiện mạo danh).

**Wireshark:** bắt gói giữa hai máy, lọc theo cổng 8000 — khung WebSocket chỉ chứa **hex bản mã**.

---

## Bảo mật trong cách dùng

**Ghép đôi: quét MỘT lần, hai bên nhớ nhau.** QR mang theo **mã ghép đôi dùng một lần** (3 từ, ví
dụ `gau-mong-nau`). Bên quét gửi kèm bằng chứng HMAC gắn với đúng phiên đó, nên bên hiện QR **tự
ghim khóa của bên quét**. Cả hai lưu nhau kèm địa chỉ, bên nào cũng gọi lại được. Mã đổi sau khi
dùng; bằng chứng gắn với transcript nên kẻ nghe lén không tái dùng được. Không quét được camera
thì đọc mã 3 từ cho nhau, hoặc dán chuỗi khóa / tải ảnh QR.

**Ai được phép kết nối vào?** Khóa lạ luôn phải qua hộp duyệt (tự từ chối sau 60 giây). Bật
**chế độ chặt** thì người lạ bị chặn thẳng. Đang trò chuyện mà có người thứ ba gọi vào → họ nhận
"bận", phiên hiện tại không bị ảnh hưởng.

**Máy đang khóa thì coi như không có mặt trên mạng.** Khi đặt mật khẩu, lúc chưa mở khóa app
không nhận kết nối, không quảng bá mDNS, không đọc được lịch sử.

**Thông báo không lộ nội dung.** Toast của Windows chỉ hiện tiêu đề kiểu *"Tin nhắn mới"* — không
tên người gửi, không nội dung (toast nằm cả trên màn hình khóa và trung tâm thông báo).

**Xóa có thùng rác (app Windows).** Xóa cuộc trò chuyện → vào mục *Đã xóa*, không tìm kiếm ra
được; khôi phục hoặc xóa vĩnh viễn (khi đó tệp dữ liệu được dọn lại để không còn sót bản mã cũ).

## App Windows — vài điều nên biết

- Bấm **✕** chỉ **thu về khay hệ thống** — app vẫn nhận tin như Zalo/Telegram. Thoát hẳn: chuột
  phải biểu tượng khiên → **Thoát Sentinell**.
- Dữ liệu ở `%APPDATA%\sentinell-desktop\` — không nằm cạnh file `.exe`; xóa `.exe` thì tài
  khoản vẫn còn.
- Cổng 8000 bị chiếm thì app tự dời sang cổng trống kế tiếp (8001…8019).
- Giao diện: 💬 Trò chuyện · 📡 LAN · 🔑 Khóa & QR · 📜 Nhật ký · 🌙 Nền sáng/tối; bảng 🛡 hiện
  **safety number** và **nhật ký giao thức** ngay cạnh khung chat.

---

## Chế độ phụ (không phải P2P đầy đủ)

Hai chế độ dưới đây chỉ để **xem thử nhanh trên máy không cài app**. Chúng **không** đáp ứng mô
hình ngang hàng như hai ứng dụng chính, và được giữ lại có chủ đích với giới hạn ghi rõ:

**Điện thoại mở bằng trình duyệt (`/join`)** — app Windows hiện QR `http://<ip>:<port>/join#k=…`,
điện thoại quét bằng camera thường → trang web **tải từ máy tính** chạy cùng lõi giao thức trong
trình duyệt và bắt tay thẳng với máy tính. Mã hóa vẫn đầu cuối (máy tính không giữ khóa của điện
thoại), **nhưng**: điện thoại phụ thuộc máy tính để tải trang, **không nhận được kết nối**, **không
lưu gì** (khóa chỉ sống trong phiên), và mã JavaScript đi qua HTTP nên phải tin mạng đang dùng —
xem mục 7b của báo cáo. Vì vậy app chỉ phục vụ trang này trong mạng con đã chọn, trong 30 phút,
kèm cảnh báo loại mạng.

**iPhone qua Expo Go** — `npm run mobile` rồi quét QR bằng Expo Go (không cần máy Mac). Expo Go
không có mô-đun native (TCP, mDNS, scrypt native) nên iPhone ở đây **chỉ gọi đi** được tới một
node đang nghe. Làm app iOS đầy đủ cần tài khoản Apple Developer hoặc máy Mac.
> iPhone báo *"You need to be signed in to Expo Go and Expo CLI"*: đăng nhập **cùng một tài khoản
> Expo** ở cả hai đầu (`npx expo login` trên PC, avatar trong app Expo Go) rồi quét lại.

## Lưu ý

- Đồ án học tập: giao thức rút gọn theo bài giảng (chưa đầy đủ như Signal X3DH/Double Ratchet),
  không thay thế ứng dụng đã được kiểm định độc lập.
- mDNS cần cùng mạng L2; mạng chặn multicast thì dùng **Kết nối thủ công (IP:cổng)**.
