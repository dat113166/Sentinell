// Trang /join — ĐIỆN THOẠI tham gia bằng trình duyệt (chế độ "Lai"), không cài gì.
// Mật mã chạy NGAY TRONG trình duyệt bằng cùng lõi @sentinell/core (bundle protocol.bundle.js);
// trang này nói chuyện thẳng với /peer của node máy tính như một peer bình thường.
//
// Trao đổi khóa qua QR: máy tính hiện QR chứa  http://<ip>:<port>/join#k=<khóa PC>&n=<tên>
// → điện thoại quét bằng camera hệ thống → mở trang này, đọc #k và GHIM khóa PC
// (out-of-band, không qua mạng) → bắt tay với expectPub = khóa PC ⇒ chống mạo danh.
import { Session, genKeypair, fingerprint, sha256Hex, isBinaryFrame, loiMoTaTep, SO_TEP_NHAN_CUNG_LUC }
  from "../vendor/protocol.bundle.js";

const $ = (id) => document.getElementById(id);
const ID_KEY = "sentinell-web-identity-v2";

// ====================================================================
// BẪY DÂY — rà xem môi trường chạy có bị can thiệp không.
//
// ĐỌC KỸ TRƯỚC KHI TIN: đây KHÔNG phải cơ chế bảo vệ. Tệp này được phục vụ công khai cho
// mọi máy trong mạng con, nên kẻ tấn công tải về đọc được hết, kể cả đoạn ngay đây. Nó gỡ
// bẫy này ra là xong. Giấu kỹ hơn cũng vô ích: bí mật đã nằm trong tay đối thủ.
//
// Vậy bẫy này để làm gì? Kẻ tấn công LƯỜI không đọc mã — nó dùng đòn tổng quát: ghi đè
// `WebSocket.prototype.send` (hoặc `fetch`, `JSON.stringify`…) để chép bản rõ TRƯỚC khi
// mã hóa. Đòn đó ăn với mọi bản dựng mà không cần hiểu gì, và nó để lại dấu: hàm bị ghi đè
// không còn là "[native code]" nữa.
//
// NGUYÊN TẮC: CHUÔNG KÊU THÌ TIN, CHUÔNG IM THÌ KHÔNG CÓ NGHĨA GÌ.
// Vì thế chỉ gửi báo động đi, KHÔNG BAO GIỜ gửi "mọi thứ ổn" — để sau này không ai dựng
// được một dấu "✅ đã xác minh" lên trên nó. (Đo được: ghi đè thường thì bẫy bắt được;
// kẻ ghi đè luôn cả Function.prototype.toString thì qua mặt được.)
// ====================================================================
function laNguyenBan(fn) {
  try { return /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn)); }
  catch { return false; }
}

function raSoatMoiTruong() {
  const nghi = [];
  const canKiem = [
    ["WebSocket.send", WebSocket.prototype.send],
    ["WebSocket", WebSocket],
    ["fetch", window.fetch],
    ["JSON.stringify", JSON.stringify],
    ["TextEncoder.encode", TextEncoder.prototype.encode],
    // Quan trọng nhất: ghi đè cái này là khóa sinh ra đoán trước được.
    ["crypto.getRandomValues", crypto.getRandomValues],
    ["XMLHttpRequest.open", XMLHttpRequest.prototype.open],
  ];
  for (const [ten, fn] of canKiem) {
    if (!laNguyenBan(fn)) nghi.push(`hàm ${ten} đã bị thay thế`);
  }
  // Script lạ trên trang: chèn thêm một thẻ <script> là đòn hay gặp nhất.
  const CHO_PHEP = ["vendor/qrcode.js", "js/join.js"];
  for (const s of document.scripts) {
    const src = s.getAttribute("src");
    if (!src) {
      if (s.dataset.sen !== "theme" && s.textContent.trim()) nghi.push("có script nội tuyến lạ trên trang");
      continue;
    }
    if (!CHO_PHEP.some((x) => src.endsWith(x))) nghi.push(`có script lạ được nạp: ${src}`);
  }
  return nghi;
}

// ---- danh tính của điện thoại (localStorage) ----
function loadIdentity() {
  try {
    const raw = localStorage.getItem(ID_KEY);
    if (raw) return JSON.parse(raw);
  } catch { /* */ }
  const kp = genKeypair();
  const id = { priv: kp.priv, pub: kp.pub, name: "Điện thoại " + fingerprint(kp.pub).slice(0, 4) };
  try { localStorage.setItem(ID_KEY, JSON.stringify(id)); } catch { /* */ }
  return id;
}
const me = loadIdentity();

// ---- đọc khóa máy tính từ QR (#k=…&n=…) ----
const hash = new URLSearchParams(location.hash.replace(/^#/, ""));
const pcPub = hash.get("k");
const pcName = hash.get("n") || "Máy tính";
const pcPairCode = hash.get("pc");   // mã ghép đôi trong QR → chứng minh để PC tự ghim mình

let ws = null, session = null;
const files = new Map();

function setConn(on, text) { $("connDot").className = "dot " + (on ? "on" : "off"); $("connText").textContent = text; }
function esc(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function log(step, detail) {
  const d = document.createElement("div");
  const cls = { "verify-ok": "ok", "safety": "ok", "derive": "ok", "verify-fail": "bad", "decrypt-fail": "bad", "warn": "warn" }[step] || "";
  d.className = "entry " + cls; d.innerHTML = `<span class="tag">${esc(step)}</span> ${esc(detail)}`;
  $("log").appendChild(d); $("log").scrollTop = $("log").scrollHeight;
}
let lastMsgMeta = null;   // {mine, ts} của bong bóng trước, để gom cụm

function fmtTime(ts) {
  try { return new Date(ts).toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" }); }
  catch { return ""; }
}
/** Gom tin cùng người gửi trong 5 phút thành một cụm, chèn vạch ngăn khi sang ngày mới. */
function addMessage(mine, body) {
  const box = $("messages");
  const ts = Date.now();
  if (!lastMsgMeta) {
    const sep = document.createElement("div");
    sep.className = "daysep";
    sep.textContent = "Hôm nay";
    box.appendChild(sep);
  }
  const grouped = lastMsgMeta && lastMsgMeta.mine === mine && (ts - lastMsgMeta.ts) < 300000;

  const el = document.createElement("div");
  el.className = "msg " + (mine ? "me" : "them") + (grouped ? " grp" : "");
  if (body.type === "file") {
    const integ = body.integrity ? "toàn vẹn ✓" : "❌ sai toàn vẹn";
    if (!body.integrity) el.classList.add("bad-integrity");
    el.innerHTML = (body.mime || "").startsWith("image/")
      ? `📎 ${esc(body.name)}<img src="${esc(body.url)}" alt="ảnh đã nhận">`
        + `<div class="meta">${integ} · ${fmtTime(ts)}</div>`
      : `📎 <a href="${esc(body.url)}" download="${esc(body.name)}">${esc(body.name)}</a>`
        + `<div class="meta">${integ} · ${fmtTime(ts)}</div>`;
  } else {
    el.innerHTML = esc(body.text) + `<div class="meta">${fmtTime(ts)}</div>`;
  }

  const prev = box.lastElementChild;
  if (grouped && prev && prev.classList.contains("msg")) prev.classList.remove("tail");
  el.classList.add("tail");

  box.appendChild(el);
  box.scrollTop = box.scrollHeight;
  lastMsgMeta = { mine, ts };
}

/** Avatar: chữ đầu từ tên, màu từ vân tay khóa. */
function paintAvatar(el, name, fp) {
  const parts = String(name || "?").trim().split(/\s+/).filter(Boolean);
  el.textContent = !parts.length ? "?"
    : parts.length === 1 ? parts[0].slice(0, 2) : parts[0][0] + parts[parts.length - 1][0];
  const hue = fp ? (parseInt(fp.slice(0, 4), 16) % 360) : 150;
  el.style.background = `hsl(${hue} 62% 62%)`;
  el.style.color = "#0d1a14";
}

// ---- chế độ màu ----
function currentTheme() {
  const set = document.documentElement.dataset.theme;
  if (set === "dark" || set === "light") return set;
  return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("sentinell-theme", t); } catch { /* */ }
  $("themeIcon").textContent = t === "dark" ? "☀️" : "🌙";
}
$("themeBtn").onclick = () => applyTheme(currentTheme() === "dark" ? "light" : "dark");
$("themeIcon").textContent = currentTheme() === "dark" ? "☀️" : "🌙";
$("logToggle").onclick = () => {
  const on = $("logWrap").classList.toggle("hidden");
  $("logToggle").classList.toggle("on", !on);
};
/** Thông báo: luôn hiện toast; khi còn ở SẢNH thì ghi thêm vào khung tin nhắn chat
 *  (khung đó đang ẩn nên trước đây thông báo rơi vào chỗ không ai nhìn thấy —
 *  bận / bị từ chối / chờ duyệt đều im lặng hoàn toàn). */
function sysMessage(text, bad, kind = "") {
  showToast(text, bad ? "bad" : kind);
  if (!$("chat").classList.contains("hidden")) {
    const el = document.createElement("div");
    el.className = "msg sys" + (bad ? " bad" : "");
    el.textContent = text;
    $("messages").appendChild(el);
    $("messages").scrollTop = $("messages").scrollHeight;
  }
}
function showToast(text, kind = "") {
  const box = $("toasts");
  const t = document.createElement("div");
  t.className = "toast " + kind;
  t.textContent = text;
  box.appendChild(t);
  while (box.children.length > 3) box.removeChild(box.firstChild);
  setTimeout(() => {
    t.classList.add("leaving");
    setTimeout(() => t.remove(), 260);
  }, 5000);
}

/** Băng trạng thái to, rõ, nằm ngay dưới nút Kết nối — thứ người dùng thật sự nhìn.
 *  `retry` = true thì kèm nút thử lại cho các trường hợp còn cứu được (bận, mất mạng). */
function showNotice(kind, title, detail, retry = false) {
  const n = $("joinNotice");
  n.className = "join-notice " + kind;
  n.innerHTML = "";
  const t = document.createElement("span");
  t.className = "jn-title";
  t.textContent = title;
  n.appendChild(t);
  if (detail) { const d = document.createElement("span"); d.textContent = detail; n.appendChild(d); }
  if (retry) {
    const b = document.createElement("button");
    b.className = "btn"; b.style.width = "100%"; b.textContent = "🔄 Thử kết nối lại";
    b.onclick = () => startJoin();
    n.appendChild(b);
  }
  n.classList.remove("hidden");
}
function hideNotice() { $("joinNotice").classList.add("hidden"); }
/** Nút Kết nối: khóa lại trong lúc đang bắt tay để khỏi bấm chồng, và nói rõ đang làm gì. */
function setJoinBusy(on, label) {
  const b = $("joinBtn");
  b.disabled = on;
  b.style.opacity = on ? "0.6" : "";
  b.innerHTML = on ? `<span class="spin">⏳</span> ${label || "Đang kết nối…"}` : "Kết nối &amp; bắt tay mã hóa";
}
// qrcode.js mặc định dùng bộ mã 'default' — nó CẮT MẤT mọi ký tự ngoài ASCII, nên mã QR
// chứa tiếng Việt (ví dụ tên "Điện thoại d85b") tạo ra vẫn quét được nhưng giải ra CHUỖI
// RỖNG. Phải chuyển sang UTF-8 ngay từ đầu. (Mã mời của máy tính thoát nạn chỉ vì tên đã
// được encodeURIComponent thành ASCII.)
if (typeof qrcode !== "undefined" && qrcode.stringToBytesFuncs && qrcode.stringToBytesFuncs["UTF-8"]) {
  qrcode.stringToBytes = qrcode.stringToBytesFuncs["UTF-8"];
}
function drawQr(container, text, cell = 4) {
  container.innerHTML = "";
  const qr = qrcode(0, "M"); qr.addData(text); qr.make();
  container.innerHTML = qr.createImgTag(cell, 8);
}

// ---- sảnh ----
$("hostInfo").textContent = `Máy tính: ${pcName} @ ${location.host}`;
if (pcPub) {
  $("pinBadge").textContent = "đã nhận khóa máy tính qua QR ✓ (" + fingerprint(pcPub).slice(0, 8) + "…)";
  $("pinBadge").className = "pill ok";
} else {
  $("pinBadge").textContent = "chưa có khóa máy tính (mở trang này bằng QR trên máy tính để có)";
  $("pinBadge").className = "pill warn";
}
// Ô 6px thay vì 4px: máy tính đọc mã này bằng cách TẢI ẢNH, mà ảnh chụp màn hình điện
// thoại hay bị thu nhỏ — 4px/ô là dưới ngưỡng đọc được.
const chuoiKhoaCuaToi = JSON.stringify({ k: me.pub, n: me.name, fp: fingerprint(me.pub) });
drawQr($("myQr"), chuoiKhoaCuaToi, 6);

/** Xuất mã QR ra PNG nét để gửi thẳng cho máy tính — khỏi phải chụp màn hình. */
function qrRaPng(text, cell = 10, margin = 4) {
  const q = qrcode(0, "M");
  q.addData(text); q.make();
  const n = q.getModuleCount();
  const cv = document.createElement("canvas");
  cv.width = cv.height = n * cell + margin * 2 * cell;
  const x = cv.getContext("2d");
  x.fillStyle = "#ffffff"; x.fillRect(0, 0, cv.width, cv.height);
  x.fillStyle = "#000000";
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (q.isDark(r, c)) x.fillRect(margin * cell + c * cell, margin * cell + r * cell, cell, cell);
    }
  }
  return cv.toDataURL("image/png");
}
$("saveMyQr").onclick = () => {
  const a = document.createElement("a");
  a.href = qrRaPng(chuoiKhoaCuaToi);
  a.download = `sentinell-dienthoai-${fingerprint(me.pub).slice(0, 8)}.png`;
  a.click();
  sysMessage("Đã lưu ảnh QR. Gửi tệp này cho máy tính, rồi ở đó bấm 📷 Quét QR → Chọn ảnh QR.", false, "good");
};
$("copyMyKey").onclick = () => {
  navigator.clipboard?.writeText(chuoiKhoaCuaToi);
  sysMessage("Đã chép chuỗi khóa. Dán vào ô nhập trong cửa sổ Quét QR của máy tính.", false, "good");
};
$("myFp").textContent = fingerprint(me.pub);
setConn(false, "chưa kết nối");

// ---- kết nối tới /peer của máy tính ----
let settled = false;   // đã có câu trả lời dứt khoát từ máy tính chưa (vào chat / bận / bị từ chối)

function startJoin() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  settled = false;
  hideNotice();
  setJoinBusy(true, "Đang gọi máy tính…");
  setConn(false, "đang gọi máy tính…");
  showNotice("wait", "⏳ Đang gọi sang máy tính…", "Chờ máy tính trả lời.");

  try { ws?.close(); } catch { /* socket cũ, kệ */ }
  ws = new WebSocket(`${proto}//${location.host}/peer`);
  ws.binaryType = "arraybuffer";      // khối tệp về dưới dạng khung nhị phân, không phải Blob
  session = new Session({ role: "I", idPriv: me.priv, idPub: me.pub, name: me.name, onLog: log, pairCode: pcPairCode });

  ws.onopen = () => {
    setConn(true, "đang trao đổi khóa…");
    setJoinBusy(true, "Đang bắt tay mã hóa…");
    showNotice("wait", "🔐 Đang bắt tay mã hóa…", "Đang trao đổi khóa với máy tính.");
    ws.send(JSON.stringify(session.hello()));
  };
  ws.onclose = () => {
    setConn(false, "đã ngắt kết nối");
    setJoinBusy(false);
    if (!$("chat").classList.contains("hidden")) {
      // Rớt giữa chừng: đưa về sảnh kèm nút nối lại, thay vì bỏ người dùng ở lại
      // một khung chat đã chết mà gõ gì cũng không gửi được.
      $("chat").classList.add("hidden");
      $("lobby").classList.remove("hidden");
      lastMsgMeta = null;
      showNotice("bad", "🔌 Cuộc trò chuyện đã kết thúc",
        "Máy tính đã ngắt kết nối hoặc mất mạng. Chế độ web không lưu lịch sử, nên tin nhắn cũ sẽ mất.", true);
      sysMessage("Kết nối đã đóng.", true);
      return;
    }
    // Đóng mà chưa có câu trả lời nào = máy tính tắt app / rớt mạng / sai địa chỉ.
    if (!settled) {
      showNotice("bad", "❌ Không kết nối được",
        "Máy tính không trả lời. Kiểm tra xem Sentinell còn mở trên máy tính và hai thiết bị có cùng WiFi không.", true);
      sysMessage("Không kết nối được tới máy tính.", true);
    }
  };
  ws.onerror = () => {
    setConn(false, "lỗi kết nối");
    setJoinBusy(false);
  };
  ws.onmessage = (ev) => {
    if (typeof ev.data === "string") { onPeer(JSON.parse(ev.data)); return; }
    onPeerBinary(new Uint8Array(ev.data));
  };
}

/** Khung nhị phân = một khối tệp. Xem chú thích khuôn khung trong core/protocol.js. */
function onPeerBinary(u8) {
  if (!session?.ready || !isBinaryFrame(u8)) return;
  let r;
  try { r = session.decryptBinary(u8, true); }
  catch { sysMessage("Một khối tệp đến bị hỏng hoặc đã bị sửa — đã bỏ qua để an toàn.", true); return; }
  if (r.mtype !== "file-chunk") return;
  if (r.meta.idx === 0) log("decrypt", `Nhận khối tệp đầu tiên: giải mã AES-256-GCM + kiểm toàn vẹn OK (seq=${r.seq}).`);
  nhanKhoi(r.meta.name, r.meta.idx, r.bytes.slice());   // bản sao riêng, khỏi giữ cả gói đã giải mã
}
$("joinBtn").onclick = () => startJoin();

function onPeer(msg) {
  if (msg.type === "busy") {
    settled = true; setConn(false, "máy tính đang bận"); setJoinBusy(false);
    showNotice("bad", "🚫 Máy tính đang bận",
      `${pcName} đang trò chuyện với một thiết bị khác. Sentinell chỉ trò chuyện với một thiết bị mỗi lần — `
      + "hãy bảo họ bấm “Ngắt kết nối” rồi thử lại.", true);
    sysMessage("Máy tính đang bận — đang trò chuyện với thiết bị khác.", true);
    return;
  }
  if (msg.type === "rejected") {
    settled = true; setConn(false, "bị từ chối"); setJoinBusy(false);
    showNotice("bad", "🚫 Máy tính từ chối kết nối", msg.reason || "", true);
    sysMessage("Máy tính từ chối kết nối. " + (msg.reason || ""), true);
    return;
  }
  if (msg.type === "pending") {
    setConn(false, "chờ máy tính duyệt"); setJoinBusy(true, "Chờ máy tính đồng ý…");
    showNotice("wait", "⏳ Đang chờ máy tính đồng ý",
      `Sang ${pcName} bấm “Chấp nhận” ở hộp “Có thiết bị xin kết nối”. Sau 60 giây không trả lời thì tự hủy.`);
    sysMessage("Sang máy tính bấm \"Chấp nhận\" để bắt đầu trò chuyện.");
    return;
  }
  if (msg.type === "hs") { ws.send(JSON.stringify(session.onHello(msg))); return; }
  if (msg.type === "hs-sig") {
    session.onSig(msg, pcPub || null);
    if (session.authFailed) {
      settled = true; setConn(false, "xác thực thất bại"); setJoinBusy(false);
      showNotice("bad", "⚠️ Xác thực THẤT BẠI — đã hủy kết nối",
        "Khóa máy tính không khớp mã QR bạn đã quét. Có thể có kẻ mạo danh đứng giữa. "
        + "Đừng nhắn gì; hãy quét lại mã QR ngay trên màn hình máy tính đó.");
      ws.close();
      return;
    }
    settled = true; hideNotice(); setJoinBusy(false);
    $("lobby").classList.add("hidden"); $("chat").classList.remove("hidden");
    $("peerName").textContent = session.peer.name;
    paintAvatar($("peerAvatar"), session.peer.name, fingerprint(session.peer.id_pub));
    $("peerFp").textContent = fingerprint(session.peer.id_pub);
    $("safetyNum").textContent = session.safety;
    const tb = $("trustBadge");
    if (session.trusted) { tb.textContent = "đã xác minh ✓"; tb.className = "pill ok"; }
    else { tb.textContent = "chưa xác minh"; tb.className = "pill warn"; }
    setConn(true, "đang trò chuyện với " + session.peer.name);

    // Gửi báo động qua ĐƯỜNG ĐÃ MÃ HÓA, không phải gói trần: kẻ tấn công muốn bịt miệng
    // nó thì phải bỏ hẳn một gói, mà bỏ gói là `seq` bên kia lệch và máy tính cảnh báo
    // ngay; sửa nội dung thì GCM từ chối. Chỉ gửi khi CÓ nghi vấn.
    const nghi = raSoatMoiTruong();
    if (nghi.length) {
      log("warn", "⚠️ Bẫy dây phát hiện môi trường bị can thiệp: " + nghi.join("; "));
      try { ws.send(JSON.stringify(session.encrypt("canary", { nghi }))); } catch { /* */ }
      sysMessage("⚠️ Trang này đang chạy trong môi trường bị can thiệp. Đã báo sang máy tính.", true);
    }
    return;
  }
  if (msg.type === "msg") {
    let obj;
    try { obj = session.decrypt(msg); } catch { sysMessage("Một tin nhắn đến bị hỏng hoặc đã bị sửa trên đường truyền — đã bỏ qua.", true); return; }
    onPlain(obj);
  }
}

function onPlain(obj) {
  if (obj.type === "text") addMessage(false, obj);
  else if (obj.type === "file-meta") {
    // Kiểm TRƯỚC khi cấp phát: mọi con số ở đây là do máy bên kia nói.
    const loi = loiMoTaTep(obj);
    if (loi) { sysMessage(`Máy tính gửi mô tả tệp không hợp lệ (${loi}) — đã bỏ qua.`, true); return; }
    if (files.size >= SO_TEP_NHAN_CUNG_LUC) { sysMessage("Đang nhận quá nhiều tệp cùng lúc — đã bỏ qua bớt.", true); return; }
    files.set(obj.name, { meta: obj, chunks: new Array(obj.chunks).fill(null), recv: 0 });
    showXfer("in", obj.name, 0, obj.chunks);
  } else if (obj.type === "file-chunk") {
    // Đường JSON+base64 — chỉ còn dùng khi đối phương chưa hiểu khung nhị phân.
    nhanKhoi(obj.name, obj.idx, b64decode(obj.data));
  }
}

/** Gộp một khối vào tệp đang nhận dở (dùng chung cho cả hai đường truyền). */
function nhanKhoi(name, idx, bytes) {
  const ent = files.get(name);
  if (!ent || ent.chunks[idx] !== null) return;
  ent.chunks[idx] = bytes;
  ent.recv++;
  showXfer("in", name, ent.recv, ent.meta.chunks);
  if (ent.recv !== ent.meta.chunks) return;

  const total = ent.chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total); let off = 0;
  for (const c of ent.chunks) { out.set(c, off); off += c.length; }
  const ok = sha256Hex(out) === ent.meta.hash;
  const url = URL.createObjectURL(new Blob([out], { type: ent.meta.mime }));
  addMessage(false, { type: "file", name: ent.meta.name, size: total, mime: ent.meta.mime, url, integrity: ok });
  files.delete(name);
}

// ---- dải tiến độ truyền tệp ----
let xferTimer = null;
function showXfer(huong, name, xong, tong) {
  const pct = tong ? Math.round((xong / tong) * 100) : 0;
  $("xferLabel").textContent = (huong === "out" ? "Đang gửi " : "Đang nhận ") + name;
  $("xferFill").style.width = pct + "%";
  $("xferPct").textContent = pct + "%";
  $("xfer").classList.remove("hidden");
  clearTimeout(xferTimer);
  xferTimer = setTimeout(() => $("xfer").classList.add("hidden"), pct >= 100 ? 900 : 8000);
}

// ---- gửi ----
function sendText() {
  const t = $("msgInput").value.trim();
  if (!t || !session?.ready) return;
  ws.send(JSON.stringify(session.encrypt("text", { text: t })));
  addMessage(true, { type: "text", text: t }); $("msgInput").value = "";
}
$("sendBtn").onclick = sendText;
$("msgInput").addEventListener("keydown", (e) => { if (e.key === "Enter") sendText(); });
const CH = 256 * 1024;
const TOI_DA_TEP = 200 * 1024 * 1024;   // trên mức này thì ôm cả tệp trong RAM điện thoại là dại

$("attachBtn").onclick = () => $("fileInput").click();
$("fileInput").addEventListener("change", async (e) => {
  const f = e.target.files[0]; e.target.value = ""; if (!f || !session?.ready) return;
  if (f.size > TOI_DA_TEP) {
    sysMessage(`Tệp nặng quá mức 200 MB mà Sentinell gửi được một lần. Hãy nén/chia nhỏ rồi gửi lại.`, true);
    return;
  }
  const buf = new Uint8Array(await f.arrayBuffer());
  const chunks = Math.max(1, Math.ceil(buf.length / CH));
  const mime = f.type || "application/octet-stream";
  const nhiPhan = session.peerBinary;

  addMessage(true, { type: "file", name: f.name, size: f.size, mime, url: URL.createObjectURL(f), integrity: true });
  ws.send(JSON.stringify(session.encrypt("file-meta", { name: f.name, size: buf.length, mime, hash: sha256Hex(buf), chunks })));
  showXfer("out", f.name, 0, chunks);

  for (let i = 0; i < chunks; i++) {
    if (!session?.ready || ws.readyState !== 1) return;
    const slice = buf.subarray(i * CH, (i + 1) * CH);
    if (nhiPhan) ws.send(session.encryptBinary("file-chunk", { name: f.name, idx: i }, slice, i !== 0));
    else ws.send(JSON.stringify(session.encrypt("file-chunk", { name: f.name, idx: i, data: b64encode(slice) })));
    showXfer("out", f.name, i + 1, chunks);
    // Nhả luồng cho trình duyệt vẽ lại, và chờ hàng đợi socket vơi bớt.
    if (ws.bufferedAmount > 4 * 1024 * 1024) await choVoiHangDoi();
    else if (i % 4 === 0) await new Promise((r) => setTimeout(r, 0));
  }
  log("encrypt", `Gửi xong "${f.name}" — ${chunks} khối, mỗi khối một khóa ratchet riêng. `
    + `Kênh: ${nhiPhan ? "khung nhị phân (bytes thẳng)" : "JSON+base64 (bản cũ)"}.`);
});

function choVoiHangDoi() {
  return new Promise((xong) => {
    const xem = setInterval(() => {
      if (!ws || ws.readyState !== 1 || ws.bufferedAmount < 4 * 1024 * 1024) { clearInterval(xem); xong(); }
    }, 20);
  });
}
$("leaveBtn").onclick = () => { if (ws) ws.close(); location.reload(); };

function b64encode(bytes) { let s = ""; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
function b64decode(str) { const s = atob(str); const out = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i); return out; }
