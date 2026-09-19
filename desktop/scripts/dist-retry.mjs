// Đóng gói .exe có tự thử lại.
// Trên Windows, electron-builder hay lỗi:
//   EPERM: operation not permitted, rename 'release\win-unpacked.tmp' -> 'release\win-unpacked'
// vì Windows Defender đang quét đống file Electron vừa giải nén nên còn giữ handle.
// Không phải lỗi mã nguồn — dọn thư mục release rồi thử lại là được.
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const releaseDir = path.resolve(here, "../release");
const MAX = 4;

const version = JSON.parse(fs.readFileSync(path.resolve(here, "../package.json"), "utf8")).version;

// electron-builder tải "winCodeSign" từ GitHub để nhúng metadata vào .exe. Ở nhiều mạng
// (kể cả mạng Việt Nam và hotspot điện thoại) GitHub không vào được → build chết dù mã nguồn
// không sao. Gặp lỗi MẠNG thì tự chuyển sang đóng gói không cần bước đó.
let khongCanMang = false;
const LOI_MANG = /ETIMEDOUT|ENOTFOUND|ECONNRESET|ECONNREFUSED|EAI_AGAIN|socket hang up|getaddrinfo|network|download/i;

/** Xóa mọi .exe không mang đúng số phiên bản đang build.
 *  `rmSync` ở đầu mỗi lần thử có lúc bị Defender giữ file nên xóa sót, để lại bản CŨ
 *  nằm cạnh bản mới — chạy nhầm rồi tưởng code không thay đổi gì. */
function xoaBanCu() {
  let files = [];
  try { files = fs.readdirSync(releaseDir); } catch { return; }
  for (const f of files) {
    if (!f.endsWith(".exe") || f.includes(version)) continue;
    const p = path.join(releaseDir, f);
    try {
      fs.rmSync(p, { force: true });
      console.log(`[dist] đã xóa bản cũ: ${f}`);
    } catch (e) {
      console.error(`[dist] ⚠ KHÔNG xóa được bản cũ "${f}" (${e.code}).`);
      console.error("       Hãy tự xóa tay, kẻo chạy nhầm bản cũ rồi tưởng code chưa đổi.");
    }
  }
}


/** electron-builder nằm ở node_modules/.bin của thư mục gốc workspace. Gọi thẳng đường dẫn
 *  thay vì trông chờ npm bơm nó vào PATH — chạy script trực tiếp là hỏng ngay. */
function timElectronBuilder() {
  const ten = process.platform === "win32" ? "electron-builder.cmd" : "electron-builder";
  for (const goc of ["../../node_modules/.bin", "../node_modules/.bin"]) {
    const p = path.resolve(here, goc, ten);
    if (fs.existsSync(p)) return `"${p}"`;
  }
  return "electron-builder";   // đành trông vào PATH
}

for (let attempt = 1; attempt <= MAX; attempt++) {
  try { fs.rmSync(releaseDir, { recursive: true, force: true }); } catch { /* */ }
  try {
    console.log(`[dist] lần thử ${attempt}/${MAX}…`);
    const desktopDir = path.resolve(here, "..");
    execSync("npm run build", { cwd: desktopDir, stdio: "inherit" });
    const themCo = khongCanMang ? " -c.win.signAndEditExecutable=false" : "";
    execSync(`${timElectronBuilder()} --win${themCo}`, { cwd: desktopDir, stdio: "inherit" });
    if (khongCanMang) {
      console.warn("[dist] ⚠ Đã đóng gói ở chế độ KHÔNG CẦN MẠNG: file .exe chạy bình thường,");
      console.warn("       nhưng phần 'Chi tiết' của file sẽ ghi Electron thay vì Sentinell.");
      console.warn("       Vào được GitHub rồi thì build lại để có metadata đầy đủ.");
    }
    xoaBanCu();
    console.log(`[dist] ĐÓNG GÓI XONG (v${version}) →`, releaseDir);
    process.exit(0);
  } catch (e) {
    if (attempt === MAX) {
      console.error("[dist] Thất bại sau", MAX, "lần. Nếu vẫn là lỗi EPERM: đóng mọi cửa sổ Sentinell,");
      console.error("       tắt phần mềm diệt virus tạm thời hoặc thêm thư mục dự án vào danh sách loại trừ, rồi chạy lại.");
      process.exit(1);
    }
    // In NGUYÊN VĂN lỗi. Trước đây dòng này đổ tại "EPERM do Defender" cho mọi lỗi,
    // che mất nguyên nhân thật (có lần là không tìm thấy electron-builder).
    console.warn(`[dist] lỗi: ${e?.message || e}`);
    const vet = `${e?.message || ""}${e?.stderr || ""}${e?.stdout || ""}`;
    if (!khongCanMang && LOI_MANG.test(vet)) {
      khongCanMang = true;
      console.warn("[dist] Có vẻ là lỗi MẠNG (electron-builder cần tải công cụ từ GitHub).");
      console.warn("[dist] → thử lại ở chế độ không cần tải gì thêm.");
    }
    console.warn("[dist] dọn rồi thử lại sau 5 giây…");
    execSync("node -e \"setTimeout(()=>{},5000)\"");
  }
}
