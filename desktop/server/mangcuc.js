// Phân loại từng card mạng: đường này là NỐI TRỰC TIẾP, mạng riêng, hay mạng công cộng?
//
// Vì sao cần: chế độ web (/join) tải mã JavaScript qua HTTP. Ai đứng được trên đường đi
// thì sửa được đoạn mã đó, và khi ấy mã hóa đầu cuối còn nguyên nhưng vô dụng — vì một
// "đầu" đã là mã của kẻ tấn công. Không có cách vá bằng mật mã (xem docs/BAOCAO.md), nên
// cách duy nhất là ĐỪNG ĐỂ AI ĐỨNG TRÊN ĐƯỜNG — và muốn thế thì người dùng phải biết
// đường mình đang dùng là loại nào.
//
// Nguyên tắc khi phân loại: NGHI NGỜ THÌ BÁO NGUY. Báo nhầm "cẩn thận" chỉ gây phiền;
// báo nhầm "an toàn" là đẩy người dùng vào đúng chỗ nguy hiểm.
import { execFile } from "node:child_process";

export const MUC = {
  TRUC_TIEP: "truc-tiep",   // hotspot của chính máy này / cáp thẳng — không có ai ở giữa
  RIENG: "rieng",           // Windows đánh dấu Private (mạng nhà, có router)
  CONG_CONG: "cong-cong",   // Windows đánh dấu Public (quán, trường, khách sạn)
  CHUA_RO: "chua-ro",       // chưa đọc được hồ sơ mạng
  CHUA_CO_MANG: "chua-co-mang",
};

const NHAN = {
  [MUC.TRUC_TIEP]: { ten: "Nối trực tiếp", an: "cao", y: "Chỉ có hai máy trên đường này — không ai chen vào giữa được." },
  [MUC.RIENG]: { ten: "Mạng riêng", an: "vua", y: "Mạng có router. Tin nhắn vẫn được mã hóa, nhưng chế độ web chỉ nên dùng nếu bạn tin mọi thiết bị trong mạng này." },
  [MUC.CONG_CONG]: { ten: "Mạng công cộng", an: "thap", y: "Windows đánh dấu đây là mạng công cộng. ĐỪNG dùng chế độ web ở đây — hãy bật điểm phát sóng của máy tính rồi cho điện thoại nối vào." },
  [MUC.CHUA_RO]: { ten: "Chưa rõ", an: "thap", y: "Chưa xác định được loại mạng — cứ coi như mạng lạ." },
  [MUC.CHUA_CO_MANG]: { ten: "Chưa có mạng", an: "thap", y: "Card này chưa xin được địa chỉ (169.254.x.x) — thường là chưa cắm hoặc chưa bật." },
};

// Các dải "chỉ có hai máy trên đường" — nhận ra được thì mới khuyên đúng.
//
// Quan trọng: điểm phát sóng chạy được theo CẢ HAI CHIỀU. Máy tính không phát được thì
// ĐIỆN THOẠI phát, máy tính nối vào — an toàn y hệt. Đây là lối thoát cho máy không có
// card WiFi phát được, hoặc cho iPhone (chưa có app riêng nên buộc dùng chế độ web).
const DAI_TRUC_TIEP = [
  { re: /^192\.168\.137\./, mask: null, ten: "Điểm phát sóng của máy tính (Windows)" },
  // iPhone cố định 172.20.10.1/28 — dải /28 rất đặc trưng, gần như không thể nhầm.
  { re: /^172\.20\.10\./, mask: "255.255.255.240", ten: "Điểm truy cập cá nhân của iPhone" },
  // Android bản gốc dùng 192.168.43.1; router nhà gần như không bao giờ chọn .43.
  { re: /^192\.168\.43\./, mask: null, ten: "Điểm phát sóng của điện thoại Android" },
];
const DAI_TU_CAP = /^169\.254\./;             // link-local: không có DHCP

/** Đoán nhanh, KHÔNG gọi tiến trình ngoài — dùng được ngay lập tức. */
export function doanNhanh(iface, ip, netmask = null) {
  for (const d of DAI_TRUC_TIEP) {
    if (!d.re.test(ip)) continue;
    // Có yêu cầu mặt nạ thì phải khớp — đó là thứ làm cho phán đoán gần như chắc chắn,
    // và ta chỉ được gắn nhãn xanh khi thật sự chắc.
    if (d.mask && netmask && netmask !== d.mask) continue;
    return MUC.TRUC_TIEP;
  }
  if (DAI_TU_CAP.test(ip)) return MUC.CHUA_CO_MANG;
  return MUC.CHUA_RO;
}

/** Tên cụ thể của đường trực tiếp, để người dùng tự kiểm chứng phán đoán của app. */
export function tenDuongTrucTiep(ip, netmask = null) {
  for (const d of DAI_TRUC_TIEP) {
    if (!d.re.test(ip)) continue;
    if (d.mask && netmask && netmask !== d.mask) continue;
    return d.ten;
  }
  return null;
}

// ---------------------------------------------------------------- hồ sơ mạng Windows
// Windows đã tự phân loại sẵn mỗi mạng là Public hay Private (chính người dùng chọn lúc
// nối vào lần đầu). Không việc gì phải đoán lại cái Windows đã biết.
//
// Nhưng gọi PowerShell mất ~3,5 GIÂY — không được chặn giao diện. Nên đọc nền, đệm lại,
// và ai hỏi trước khi có kết quả thì trả về "chưa rõ" (tức là phía an toàn).
let demHoSo = null;          // { [tenCard]: MUC }
let dangDoc = null;
let docLuc = 0;
const HAN_DEM_MS = 30_000;

function docHoSoWindows() {
  if (process.platform !== "win32") return Promise.resolve({});
  if (dangDoc) return dangDoc;
  dangDoc = new Promise((xong) => {
    execFile("powershell", [
      "-NoProfile", "-NonInteractive", "-Command",
      "Get-NetConnectionProfile | Select-Object InterfaceAlias,NetworkCategory | ConvertTo-Json -Compress",
    ], { timeout: 9000, windowsHide: true }, (loi, ra) => {
      dangDoc = null;
      if (loi) { xong(demHoSo || {}); return; }
      try {
        const j = JSON.parse(String(ra).trim() || "[]");
        const ds = Array.isArray(j) ? j : [j];
        const bang = {};
        for (const p of ds) {
          if (!p?.InterfaceAlias) continue;
          // NetworkCategory: 0 = Public, 1 = Private, 2 = DomainAuthenticated.
          // Có bản trả về chuỗi ("Public"/"Private") nên nhận cả hai kiểu.
          const c = p.NetworkCategory;
          const cong = c === 0 || c === "Public";
          bang[p.InterfaceAlias] = cong ? MUC.CONG_CONG : MUC.RIENG;
        }
        demHoSo = bang;
        docLuc = Date.now();
        xong(bang);
      } catch {
        xong(demHoSo || {});
      }
    });
  });
  return dangDoc;
}

/** Gọi sớm để kết quả sẵn sàng trước khi người dùng mở cửa sổ QR. */
export function hamNong() {
  docHoSoWindows().catch(() => {});
}

/** Đọc lại nếu bản đệm đã cũ — không chờ, lần hỏi sau sẽ có số mới. */
function lamMoiNeuCu() {
  if (!demHoSo || Date.now() - docLuc > HAN_DEM_MS) docHoSoWindows().catch(() => {});
}

/** Gắn nhãn an toàn cho danh sách địa chỉ. Luôn trả lời NGAY, dùng bản đệm nếu có. */
export function ganNhan(dsIps) {
  lamMoiNeuCu();
  return dsIps.map((d) => {
    let muc = doanNhanh(d.iface, d.ip, d.netmask);
    // Hồ sơ của Windows chỉ dùng khi chưa chắc chắn — dải hotspot thì đã chắc rồi,
    // đừng để Windows đánh dấu nó là "Public" rồi báo động nhầm.
    if (muc === MUC.CHUA_RO && demHoSo && demHoSo[d.iface]) muc = demHoSo[d.iface];
    const n = NHAN[muc] || NHAN[MUC.CHUA_RO];
    const ten = tenDuongTrucTiep(d.ip, d.netmask);
    return {
      ...d, muc, nhan: n.ten, an: n.an,
      // Nói rõ app nhận ra CÁI GÌ, để người dùng tự kiểm chứng chứ không phải tin suông.
      y: ten ? `${ten}. ${n.y}` : n.y,
    };
  });
}

// ------------------------------------------------------------ rà dấu vết kẻ đứng giữa
//
// KHÔNG kiểm tra được tệp JS trên điện thoại có bị sửa hay không — muốn kiểm thì phải hỏi
// chính đoạn mã đã bị sửa, mà nó thì nói dối. Nhưng kẻ tấn công muốn chen vào giữa hai máy
// trong mạng LAN thì cách phổ biến nhất là GIẢ MẠO ARP: nó bảo với máy bạn "tôi là router",
// và bảo với router "tôi là máy bạn". Việc đó để lại dấu vết NGAY TRÊN MÁY NÀY:
//
//   • một địa chỉ MAC đứng tên NHIỀU địa chỉ IP  → gần như chắc chắn là giả mạo
//   • MAC của một địa chỉ ĐỔI giữa chừng         → có kẻ vừa chen vào
//
// Không bắt được mọi kiểu (điểm phát sóng giả, hay chính router bị chiếm thì chịu), nhưng
// bắt được kiểu hay gặp nhất, và bắt NGAY trong lúc ghép đôi — trước khi kịp nhắn gì.
let macDaThay = new Map();      // ip -> mac lần đầu thấy
let demLangGieng = null;
let dangDocLg = null;
let docLgLuc = 0;

const LOC_PS = `
Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object {
    $_.State -in 'Reachable','Stale','Permanent' -and
    $_.LinkLayerAddress -match '^([0-9A-F]{2}-){5}[0-9A-F]{2}$' -and
    $_.LinkLayerAddress -notmatch '^(01-00-5E|FF-FF-FF)' -and
    $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and
    ($_.IPAddress -split '\\.')[0] -as [int] -lt 224
  } | Select-Object IPAddress,LinkLayerAddress | ConvertTo-Json -Compress`;

function docLangGieng() {
  if (process.platform !== "win32") return Promise.resolve([]);
  if (dangDocLg) return dangDocLg;
  dangDocLg = new Promise((xong) => {
    execFile("powershell", ["-NoProfile", "-NonInteractive", "-Command", LOC_PS],
      { timeout: 9000, windowsHide: true }, (loi, ra) => {
        dangDocLg = null;
        if (loi) { xong(demLangGieng || []); return; }
        try {
          const j = JSON.parse(String(ra).trim() || "[]");
          demLangGieng = (Array.isArray(j) ? j : [j])
            .filter((x) => x?.IPAddress)
            .map((x) => ({ ip: x.IPAddress, mac: x.LinkLayerAddress }));
          docLgLuc = Date.now();
        } catch { /* giữ bản đệm cũ */ }
        xong(demLangGieng || []);
      });
  });
  return dangDocLg;
}

/** Rà mạng con đang dùng. Trả lời NGAY bằng bản đệm; lần hỏi sau có số mới hơn. */
export function raMang(diaChiCuaToi, netmask) {
  if (!demLangGieng || Date.now() - docLgLuc > 15_000) docLangGieng().catch(() => {});
  if (!demLangGieng) return { xong: false, nghiNgo: false, soLangGieng: 0, dauHieu: [] };
  return phanTichLangGieng(demLangGieng, diaChiCuaToi, netmask);
}

/** Phần PHÂN TÍCH tách riêng khỏi phần đọc hệ thống — để kiểm thử được bằng bảng giả,
 *  chứ không phải chờ có kẻ tấn công thật mới biết nhánh cảnh báo có chạy hay không. */
export function phanTichLangGieng(dsLangGieng, diaChiCuaToi, netmask) {
  const trong = dsLangGieng.filter((n) => cungMangCon(n.ip, diaChiCuaToi, netmask));
  const dauHieu = [];

  // 1) Một MAC đứng tên nhiều IP.
  const theoMac = new Map();
  for (const n of trong) {
    if (!theoMac.has(n.mac)) theoMac.set(n.mac, new Set());
    theoMac.get(n.mac).add(n.ip);
  }
  for (const [mac, ips] of theoMac) {
    if (ips.size > 1) {
      dauHieu.push(`Một thiết bị (${mac}) đang nhận mình là ${ips.size} địa chỉ khác nhau: `
        + `${[...ips].join(", ")}. Đây là dấu hiệu điển hình của giả mạo ARP.`);
    }
  }

  // 2) MAC của một địa chỉ đổi giữa chừng.
  for (const n of trong) {
    const cu = macDaThay.get(n.ip);
    if (cu && cu !== n.mac) {
      dauHieu.push(`Địa chỉ ${n.ip} vừa đổi thiết bị (${cu} → ${n.mac}) — có thể có kẻ vừa chen vào.`);
    }
    macDaThay.set(n.ip, n.mac);
  }

  return { xong: true, nghiNgo: dauHieu.length > 0, soLangGieng: trong.length, dauHieu };
}

/** Quên nền cũ (đổi mạng thì MAC đổi là chuyện bình thường, đừng báo động nhầm). */
export function quenNenArp() { macDaThay = new Map(); }

/** Cùng một mạng con? Dùng để chỉ phục vụ /join cho đúng card mạng đã chọn. */
export function cungMangCon(a, b, netmask) {
  if (!a || !b) return false;
  const so = (s) => s.split(".").map(Number);
  const [x, y, m] = [so(a), so(b), so(netmask || "255.255.255.0")];
  if (x.length !== 4 || y.length !== 4 || m.length !== 4) return false;
  return x.every((v, i) => (v & m[i]) === (y[i] & m[i]));
}
