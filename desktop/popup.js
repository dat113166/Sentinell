// Cửa sổ thông báo của RIÊNG Sentinell.
//
// Vì sao không dùng toast của Windows: toast chỉ chuyển cú bấm trở lại cho app qua một cơ
// chế đăng ký mà bản portable (chạy từ %TEMP%, không cài đặt) không thỏa được. Đã thử ba
// cách — giữ tham chiếu Notification, tạo lối tắt Start Menu, bong bóng khay — cú bấm đều
// không tới nơi. Cửa sổ này là của chính app nên cú bấm là chuyện nội bộ.
//
// Đổi lại: thông báo KHÔNG vào trung tâm thông báo của Windows và không hiện trên màn hình
// khóa — với một app nhắn tin mã hóa đầu cuối thì đó lại là điều tốt.
import { BrowserWindow, screen } from "electron";

// Cửa sổ rộng hơn tấm thẻ bên trong: chừa chỗ cho bóng đổ và góc bo, nếu không
// góc tròn sẽ bị cắt cụt ở mép cửa sổ.
const RONG = 384;
const CAO = 116;
const LE = 10;             // khoảng chừa quanh thẻ
const GIU_MS = 6000;

let win = null;
let hetGio = null;
let khiBam = null;         // gọi khi người dùng bấm vào thông báo

/** Trang thông báo — nhúng thẳng bằng data URL, không cần preload hay tệp rời.
 *  Cú bấm bắt qua `will-navigate` tới sentinell://mo (mẹo tránh phải dựng IPC). */
function trangHtml(tieuDe, phu, coAmThanh) {
  const esc = (s) => String(s).replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  // Chuông ngắn hai nốt, dựng bằng Web Audio — khỏi phải kèm tệp âm thanh nào.
  const amThanh = coAmThanh ? `
  try {
    const ac = new AudioContext();
    const keu = (tanSo, batDau, dai, to) => {
      const o = ac.createOscillator(), g = ac.createGain();
      o.type = "sine"; o.frequency.value = tanSo;
      o.connect(g); g.connect(ac.destination);
      const t = ac.currentTime + batDau;
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(to, t + 0.015);
      g.gain.exponentialRampToValueAtTime(0.0001, t + dai);
      o.start(t); o.stop(t + dai + 0.02);
    };
    keu(880, 0,    0.16, 0.18);   // nốt cao
    keu(1320, 0.11, 0.22, 0.13);  // nốt cao hơn, chồng nhẹ lên
  } catch (e) { /* không phát được thì thôi, thông báo vẫn hiện */ }` : "";

  return "data:text/html;charset=utf-8," + encodeURIComponent(`<!doctype html>
<meta charset="utf-8">
<style>
  * { box-sizing: border-box; margin: 0; }
  html, body { height: 100%; background: transparent; overflow: hidden;
    font-family: system-ui, "Segoe UI", Roboto, sans-serif; -webkit-user-select: none; }
  body { padding: ${LE}px; }

  a.the {
    display: flex; align-items: center; gap: 13px; height: 100%;
    padding: 14px 16px; text-decoration: none; cursor: pointer; color: #e9eeff;
    /* Bo tròn sâu kiểu kính: nền hơi trong, viền sáng mảnh, cộng một vệt sáng
       ở mép trên để trông như có độ dày. */
    border-radius: 22px;
    background:
      linear-gradient(160deg, rgba(38,52,86,.92) 0%, rgba(17,24,44,.94) 58%),
      rgba(17,24,44,.9);
    border: 1px solid rgba(255,255,255,.13);
    box-shadow:
      inset 0 1px 0 rgba(255,255,255,.14),
      inset 0 -1px 0 rgba(0,0,0,.28),
      0 14px 38px rgba(0,0,0,.52);
    transition: background .12s ease;
  }
  a.the:hover { background: linear-gradient(160deg, rgba(46,62,100,.95) 0%, rgba(22,30,54,.96) 58%); }

  .khien {
    width: 42px; height: 42px; flex: none; border-radius: 14px;
    display: grid; place-items: center; font-size: 22px;
    background: rgba(61,220,151,.16);
    border: 1px solid rgba(61,220,151,.34);
  }
  /* Bọc để nút ✕ bám đúng góc TẤM THẺ, không phụ thuộc kích thước cửa sổ. */
  .boc { position: relative; height: 100%; }
  .dong {
    position: absolute; top: 9px; right: 10px;
    width: 24px; height: 24px; border-radius: 50%;
    display: grid; place-items: center; text-decoration: none;
    font-size: 13px; line-height: 1; color: #8b9ac0;
    background: rgba(255,255,255,.05); border: 1px solid rgba(255,255,255,.09);
    transition: background .12s ease, color .12s ease;
  }
  .dong:hover { background: rgba(255,255,255,.14); color: #eaf0ff; }

  .chu { min-width: 0; flex: 1; display: flex; flex-direction: column; gap: 3px;
         padding-right: 26px; }   /* chừa chỗ cho nút ✕, chữ không chui xuống dưới nó */
  .td { font-size: 14.5px; font-weight: 650; letter-spacing: .1px;
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  /* Cho phép xuống DÒNG THỨ HAI thay vì cắt cụt — câu dài vẫn đọc được đủ ý. */
  .phu { font-size: 12.5px; line-height: 1.35; color: #9fadcc;
         display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;
         overflow: hidden; }
  .ten { font-size: 10px; letter-spacing: .3px; color: #5d6c92; margin-top: 2px; }
</style>
<div class="boc">
  <a class="the" href="sentinell://mo">
    <span class="khien">🛡️</span>
    <span class="chu">
      <span class="td">${esc(tieuDe)}</span>
      <span class="phu">${esc(phu)}</span>
      <span class="ten">Sentinell</span>
    </span>
  </a>
  <a class="dong" href="sentinell://dong" title="Đóng thông báo">✕</a>
</div>
<script>${amThanh}</script>`);
}

function taoCuaSo() {
  if (win && !win.isDestroyed()) return win;
  win = new BrowserWindow({
    width: RONG, height: CAO,
    show: false, frame: false, transparent: true, hasShadow: false,
    resizable: false, movable: false, minimizable: false, maximizable: false,
    skipTaskbar: true, alwaysOnTop: true,
    focusable: false,          // không cướp tiêu điểm của việc đang làm
    webPreferences: { contextIsolation: true, sandbox: true },
  });
  win.setAlwaysOnTop(true, "screen-saver");   // nổi trên cả cửa sổ toàn màn hình
  win.setMenuBarVisibility(false);

  // Trang chỉ có hai liên kết: bấm vào thẻ (mở app) và bấm ✕ (chỉ đóng thông báo).
  // Chặn điều hướng rồi phân luồng theo địa chỉ — khỏi phải dựng preload/IPC.
  const batBam = (e, url) => {
    e.preventDefault();
    const u = String(url);
    if (u.startsWith("sentinell://dong")) { an(); return; }
    if (u.startsWith("sentinell://mo")) { an(); khiBam?.(); }
  };
  win.webContents.on("will-navigate", batBam);
  win.webContents.on("will-redirect", batBam);
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  return win;
}

/** Đặt ở góc dưới bên phải vùng làm việc (trên thanh tác vụ). */
function datViTri(w) {
  const { workArea } = screen.getPrimaryDisplay();
  w.setBounds({
    x: workArea.x + workArea.width - RONG - 12,
    y: workArea.y + workArea.height - CAO - 12,
    width: RONG, height: CAO,
  });
}

export function hienPopup(tieuDe, phu, onClick, coAmThanh = true) {
  khiBam = onClick;
  const w = taoCuaSo();
  w.loadURL(trangHtml(tieuDe, phu, coAmThanh));
  datViTri(w);
  w.showInactive();            // hiện mà KHÔNG giành tiêu điểm
  clearTimeout(hetGio);
  hetGio = setTimeout(an, GIU_MS);
}

export function an() {
  clearTimeout(hetGio);
  hetGio = null;
  if (win && !win.isDestroyed() && win.isVisible()) win.hide();
}

export function dong() {
  clearTimeout(hetGio);
  if (win && !win.isDestroyed()) win.destroy();
  win = null;
}
