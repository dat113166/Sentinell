// Điểm vào Electron — app desktop Sentinell trên PC.
//   • Khởi động máy chủ cục bộ (server/index.js) rồi mở cửa sổ tới http://127.0.0.1:<port>/
//   • Bọc khóa bí mật trên đĩa bằng safeStorage (DPAPI / Keychain).
//   • Tham số: --port <n>  --data <thư mục>   (để chạy 2 bản trên cùng máy khi thử)
import { app, BrowserWindow, Menu, Tray, nativeImage, clipboard, dialog, safeStorage, shell } from "electron";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
// Luôn nạp bản bundle (dist/server.mjs, do esbuild gộp core + @noble) — đây là thứ duy nhất
// được đóng vào app.asar; ở chế độ dev `npm start` cũng build bundle trước khi chạy.
import { startServer } from "./dist/server.mjs";
import { hienPopup, dong as dongPopup } from "./popup.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(1);
const arg = (k, d) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d; };

const PORT = Number(arg("--port", process.env.SENTINELL_PORT || 8000));
const DATA = arg("--data", null);

// Cho phép chạy nhiều bản với --data khác nhau (mỗi bản một userData riêng).
if (DATA) app.setPath("userData", path.resolve(DATA));

function webDir() {
  return app.isPackaged ? path.join(process.resourcesPath, "web") : path.join(__dirname, "..", "web");
}

function protect() {
  if (!safeStorage.isEncryptionAvailable()) return null;
  return {
    encrypt: (s) => safeStorage.encryptString(s).toString("base64"),
    decrypt: (s) => safeStorage.decryptString(Buffer.from(s, "base64")),
  };
}

let running = null;
let win = null;
let tray = null;
let dangThoatHan = false;      // true khi người dùng thật sự chọn Thoát
let batThongBao = true;        // có bắn thông báo Windows hay không

// Cho phép trang thông báo tự phát âm thanh (Chromium mặc định chặn khi chưa có thao tác
// của người dùng — mà thông báo thì theo định nghĩa là chưa ai bấm gì cả).
app.commandLine.appendSwitch("autoplay-policy", "no-user-gesture-required");

/** Icon cửa sổ (nút trên thanh tác vụ). Đọc thành nativeImage để nếu tệp hỏng thì biết
 *  ngay, thay vì Windows lặng lẽ rơi về icon mặc định của Electron. */
function anhIcon() {
  const a = nativeImage.createFromPath(duongDanAsset("icon.png"));
  if (a.isEmpty()) ghiNhatKy("CANH BAO: khong doc duoc assets/icon.png");
  return a;
}

function duongDanAsset(ten) {
  return app.isPackaged
    ? path.join(process.resourcesPath, "assets", ten)
    : path.join(__dirname, "assets", ten);
}

async function createWindow() {
  running = await startServer({
    dataDir: path.join(app.getPath("userData"), "sentinell-data"),
    port: PORT,
    webDir: webDir(),
    protect: protect(),
  });
  const boundPort = running.port; // có thể khác PORT nếu cổng mặc định bận
  win = new BrowserWindow({
    width: 1200, height: 800, minWidth: 900, minHeight: 600,
    title: "Sentinell",
    backgroundColor: "#0b1020",
    icon: anhIcon(),
    webPreferences: { contextIsolation: true, sandbox: true },
  });
  win.setMenuBarVisibility(false);
  // Link ngoài mở bằng trình duyệt hệ thống
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: "deny" }; });
  ganMenuChuotPhai(win);

  // Bấm ✕ chỉ THU VỀ KHAY như mọi app nhắn tin — muốn tắt hẳn phải chọn Thoát
  // trong menu chuột phải của biểu tượng khay.
  win.on("close", (e) => {
    if (dangThoatHan) return;
    e.preventDefault();
    win.hide();
    if (!win.daBaoThuKhay) {
      win.daBaoThuKhay = true;
      hienThongBao("Sentinell vẫn đang chạy",
        "Đã thu về khay để vẫn nhận tin. Chuột phải biểu tượng khiên → Thoát để tắt hẳn.",
        false);   // thu về khay thì không cần kêu
    }
  });

  ghiNhatKy(`--- khoi dong | dong goi=${app.isPackaged}`
    + ` | portable=${process.env.PORTABLE_EXECUTABLE_FILE ? "co" : "khong"}`
    + ` | icon doc duoc=${!anhIcon().isEmpty()}`);
  donLoiTatHong();
  taoKhayHeThong(boundPort);

  // Thông báo — chỉ bắn khi người dùng KHÔNG nhìn cửa sổ.
  //
  // Cố ý KHÔNG hiện tên người gửi hay nội dung tin, chỉ hiện tiêu đề. Đây là app nhắn tin
  // mã hóa đầu cuối: ai liếc qua màn hình cũng không được đọc ké nội dung.
  const NHAN = {
    message:   ["Tin nhắn mới", "Mở Sentinell để xem."],
    approval:  ["Thiết bị mới xin kết nối", "Mở Sentinell để duyệt."],
    connected: ["Thiết bị mới kết nối", "Mở Sentinell để xem."],
  };
  running.node.onNotify = (loai) => {
    if (!batThongBao) return;
    if (win && win.isVisible() && !win.isMinimized() && win.isFocused()) return;
    const [tieuDe, phu] = NHAN[loai] || NHAN.message;
    hienThongBao(tieuDe, phu);
  };

  await win.loadURL(`http://127.0.0.1:${boundPort}/`);
}

function hienThongBao(tieuDe, noiDung, coAmThanh = true) {
  ghiNhatKy(`hien popup: "${tieuDe}" | am thanh=${coAmThanh}`);
  hienPopup(tieuDe, noiDung, () => {
    ghiNhatKy("popup: NGUOI DUNG BAM");
    hienCuaSo();
  }, coAmThanh);
}

/** Nhật ký chẩn đoán cho phần thông báo.
 *  CỐ Ý không ghi tên người gửi hay nội dung tin — chỉ ghi sự kiện và trạng thái cửa sổ. */
function ghiNhatKy(dong) {
  try {
    const f = path.join(app.getPath("userData"), "nhat-ky-thong-bao.log");
    fs.appendFileSync(f, `[${new Date().toISOString()}] ${dong}\n`);
  } catch { /* ghi được thì ghi, không thì thôi */ }
}

/** Đưa cửa sổ ra trước cho BẰNG ĐƯỢC.
 *  Windows chặn tiến trình nền cướp tiêu điểm, nên `win.focus()` trơ một mình thường
 *  không ăn thua — phải hiện ra, ghim tạm lên trên cùng rồi nhả ra ngay. */
function hienCuaSo() {
  if (!win) { ghiNhatKy("hienCuaSo: KHONG CO cua so"); return; }
  ghiNhatKy(`hienCuaSo: truoc -> hien=${win.isVisible()} thuNho=${win.isMinimized()} focus=${win.isFocused()}`);
  if (win.isMinimized()) win.restore();
  if (!win.isVisible()) win.show();
  win.setAlwaysOnTop(true);
  win.show();
  win.setAlwaysOnTop(false);
  app.focus({ steal: true });
  win.focus();
  ghiNhatKy(`hienCuaSo: sau  -> hien=${win.isVisible()} thuNho=${win.isMinimized()} focus=${win.isFocused()}`);
}

/** Bản 3.3.1–3.3.2 từng tạo một lối tắt trong Start Menu để cố làm cho toast chuẩn của
 *  Windows bấm được. Cách đó KHÔNG hiệu quả với bản portable, nên thôi không tạo nữa —
 *  và dọn luôn cái lối tắt hỏng đã lỡ tạo (chỉ khi nó trỏ vào thư mục tạm, tức chắc chắn
 *  là của ta và chắc chắn vô dụng; lối tắt do bộ cài NSIS tạo thì không đụng tới). */
function donLoiTatHong() {
  if (process.platform !== "win32") return;
  try {
    const duong = path.join(app.getPath("appData"),
      "Microsoft", "Windows", "Start Menu", "Programs", "Sentinell.lnk");
    if (!fs.existsSync(duong)) return;
    const l = shell.readShortcutLink(duong);
    if (l.target && laThuMucTam(l.target)) fs.rmSync(duong, { force: true });
  } catch { /* không đọc được thì để yên, không xóa bừa */ }
}

/** Đường dẫn có nằm trong thư mục tạm của Windows không. */
function laThuMucTam(p) {
  const tam = (process.env.TEMP || process.env.TMP || "").toLowerCase();
  const q = p.toLowerCase();
  return Boolean((tam && q.startsWith(tam)) || q.includes("\\appdata\\local\\temp\\"));
}

/** Biểu tượng khay: đủ dùng, không nhồi nhét. */
function taoKhayHeThong(port) {
  const anh = nativeImage.createFromPath(duongDanAsset("tray.png"));
  tray = new Tray(anh.isEmpty() ? nativeImage.createEmpty() : anh);
  tray.setToolTip(`Sentinell — đang chạy ở cổng ${port}`);
  tray.on("click", () => hienCuaSo());          // bấm một lần cũng mở, khỏi phải nhớ bấm đúp
  tray.on("double-click", () => hienCuaSo());
  veMenuKhay();
}

function veMenuKhay() {
  // Giữ đúng ba mục — menu khay càng gọn càng dễ dùng.
  const menu = Menu.buildFromTemplate([
    { label: "Mở", click: () => hienCuaSo() },
    { label: "Thông báo", type: "checkbox", checked: batThongBao,
      click: (m) => { batThongBao = m.checked; } },
    { type: "separator" },
    { label: "Thoát", click: () => { dangThoatHan = true; app.quit(); } },
  ]);
  tray.setContextMenu(menu);
}

/** Electron KHÔNG có sẵn menu chuột phải — không gắn thì bấm chuột phải chẳng ra gì,
 *  mất cả Cắt/Chép/Dán và Chọn tất cả trong các ô nhập. */
function ganMenuChuotPhai(win) {
  win.webContents.on("context-menu", (_e, p) => {
    const muc = [];

    if (p.linkURL) {
      muc.push(
        { label: "Mở liên kết bằng trình duyệt", click: () => shell.openExternal(p.linkURL) },
        { label: "Chép địa chỉ liên kết", click: () => clipboard.writeText(p.linkURL) },
        { type: "separator" },
      );
    }
    if (p.mediaType === "image" && p.srcURL) {
      muc.push(
        { label: "Chép ảnh", click: () => win.webContents.copyImageAt(p.x, p.y) },
        { label: "Lưu ảnh về máy…", click: () => win.webContents.downloadURL(p.srcURL) },
        { type: "separator" },
      );
    }

    const oNhap = p.isEditable;
    const coChon = !!(p.selectionText && p.selectionText.trim());
    if (oNhap || coChon) {
      muc.push(
        { label: "Hoàn tác", role: "undo", enabled: oNhap && p.editFlags.canUndo },
        { label: "Làm lại", role: "redo", enabled: oNhap && p.editFlags.canRedo },
        { type: "separator" },
        { label: "Cắt", role: "cut", enabled: oNhap && p.editFlags.canCut },
        { label: "Chép", role: "copy", enabled: p.editFlags.canCopy },
        { label: "Dán", role: "paste", enabled: oNhap && p.editFlags.canPaste },
        { label: "Chọn tất cả", role: "selectAll", enabled: p.editFlags.canSelectAll },
      );
    }

    if (muc.length) muc.push({ type: "separator" });
    muc.push(
      { label: "Tải lại giao diện", click: () => win.webContents.reload() },
      { label: "Công cụ nhà phát triển", click: () => win.webContents.toggleDevTools() },
    );

    Menu.buildFromTemplate(muc).popup({ window: win });
  });
}

app.whenReady().then(createWindow).catch((e) => {
  // Đừng thoát im lặng — người dùng cuối cần biết vì sao app không mở.
  console.error(e);
  dialog.showErrorBox(
    "Sentinell không khởi động được",
    `${e?.message || e}\n\nGợi ý: đóng bớt ứng dụng đang chiếm cổng mạng, hoặc chạy lại với\n` +
    `tham số --port <số cổng khác>.`
  );
  app.quit();
});
// Đóng cửa sổ KHÔNG còn là thoát app (nó chỉ thu về khay), nên chỉ dọn dẹp khi
// người dùng thật sự chọn Thoát.
app.on("window-all-closed", () => { if (dangThoatHan) app.quit(); });

app.on("before-quit", async (e) => {
  if (!running || running.daDon) return;
  e.preventDefault();
  dangThoatHan = true;
  // Chốt chặn cuối: dù dọn dẹp có kẹt ở đâu thì cũng phải thoát, không để lại tiến
  // trình "ma" giữ cổng — đó là thứ làm mã QR cũ trỏ vào một máy chủ đã chết.
  const thoatEp = setTimeout(() => app.exit(0), 3000);
  try { await running.stop(); } catch (err) { console.error("stop():", err); }
  clearTimeout(thoatEp);
  running.daDon = true;
  try { dongPopup(); } catch { /* */ }
  try { tray?.destroy(); } catch { /* */ }
  app.quit();
});
