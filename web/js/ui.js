import { parseQr } from "../vendor/protocol.bundle.js";

// Sentinell — giao diện thin-client, nói chuyện với node cục bộ qua WebSocket /ui.
// Mọi mật mã & lưu trữ nằm ở node; file này chỉ lo hiển thị và thao tác.

const $ = (id) => document.getElementById(id);
let ws = null;
let myState = null;
let peers = [];
let scanStream = null;
let scanRAF = null;
let scannedPairCode = null;   // mã ghép đôi vừa quét được của đối phương
let scannedPairPub = null;
let inviteUrl = "";           // liên kết mời hiện tại (nội dung của mã QR)
let modalTimer = null;        // đếm ngược tự đóng cửa sổ QR sau khi đã kết nối
let raTimer = null;           // nhịp hỏi lại kết quả rà mạng khi cửa sổ QR đang mở
let activeTab = "chats";
let previews = {};            // fp → {preview, ts, direction} cập nhật tại chỗ khi có tin mới
let lastMsgMeta = null;       // {direction, ts} của bong bóng trước, để gom cụm
let timKiem = "";             // từ khóa đang gõ ở ô tìm kiếm ("" = không tìm)
let ketQuaTin = null;         // kết quả tin nhắn gần nhất, để vẽ lại khi danh bạ đổi
let chuKyDanhBa = "";         // "chữ ký" danh bạ, để biết khi nào phải tìm lại
let xemLai = null;            // liên hệ đang XEM LẠI lịch sử dù chưa kết nối
let nhayToi = null;           // ts của tin nhắn cần nhảy tới sau khi nạp xong lịch sử

// ================================================================ chế độ màu
function currentTheme() {
  const set = document.documentElement.dataset.theme;
  if (set === "dark" || set === "light") return set;
  return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("sentinell-theme", t); } catch { /* bị chặn thì thôi */ }
  $("themeIcon").textContent = t === "dark" ? "☀️" : "🌙";
}
$("themeBtn").onclick = () => applyTheme(currentTheme() === "dark" ? "light" : "dark");
$("themeIcon").textContent = currentTheme() === "dark" ? "☀️" : "🌙";

// ================================================================ kết nối WS
function connectWS() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${proto}//${location.host}/ui`);
  ws.onopen = () => { setConn(true, "sẵn sàng"); send({ cmd: "get_state" }); };
  ws.onclose = () => { setConn(false, "mất kết nối — đang thử lại…"); setTimeout(connectWS, 1500); };
  ws.onmessage = (ev) => handleEvent(JSON.parse(ev.data));
}
function send(obj) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj)); }

/** Gửi tệp sang node dưới dạng bytes thô, KHÔNG qua base64.
 *  Khuôn khung:  u16BE(độ dài phần đầu) ‖ phần đầu JSON ‖ bytes tệp. */
function sendFileFrame(dau, bytes) {
  if (!(ws && ws.readyState === 1)) return false;
  const dauBytes = new TextEncoder().encode(JSON.stringify(dau));
  const khung = new Uint8Array(2 + dauBytes.length + bytes.length);
  khung[0] = dauBytes.length >>> 8;
  khung[1] = dauBytes.length & 0xff;
  khung.set(dauBytes, 2);
  khung.set(bytes, 2 + dauBytes.length);
  ws.send(khung);
  return true;
}
function setConn(on, text) {
  $("connDot").className = "dot " + (on ? "on" : "off");
  $("connText").textContent = text;
}

// ================================================================ khóa & tài khoản
/** Hộp hỏi mật khẩu. Electron KHÔNG có window.prompt (gọi là trơ, không hiện gì),
 *  nên phải tự dựng. Trả về mật khẩu, hoặc null nếu người dùng hủy. */
function hoiMatKhau({ tieuDe, moTa, coCu = false, coNhacLai = true, nutOk = "Xác nhận" }) {
  return new Promise((tra) => {
    $("pwTitle").textContent = tieuDe;
    $("pwDesc").textContent = moTa;
    $("pwOld").classList.toggle("hidden", !coCu);
    $("pwNew2").classList.toggle("hidden", !coNhacLai);
    $("pwGo").textContent = nutOk;
    for (const id of ["pwOld", "pwNew", "pwNew2"]) $(id).value = "";
    $("pwErr").classList.add("hidden");
    $("pwModal").classList.remove("hidden");
    setTimeout(() => $(coCu ? "pwOld" : "pwNew").focus(), 30);

    const dong = (kq) => {
      $("pwModal").classList.add("hidden");
      $("pwGo").onclick = null; $("pwCancel").onclick = null;
      $("pwModal").onkeydown = null;
      for (const id of ["pwOld", "pwNew", "pwNew2"]) $(id).value = "";
      tra(kq);
    };
    const bao = (t) => { $("pwErr").textContent = t; $("pwErr").classList.remove("hidden"); };
    const xong = () => {
      const moi = $("pwNew").value;
      if (coNhacLai && moi !== $("pwNew2").value) { bao("Hai ô mật khẩu không khớp nhau."); return; }
      if (!moi) { bao("Chưa nhập mật khẩu."); return; }
      dong({ cu: $("pwOld").value, moi });
    };
    $("pwGo").onclick = xong;
    $("pwCancel").onclick = () => dong(null);
    $("pwModal").onkeydown = (e) => {
      if (e.key === "Enter") xong();
      if (e.key === "Escape") dong(null);
    };
  });
}

function renderLock(m) {
  const khoa = !!m.locked;
  $("lockScreen").classList.toggle("hidden", !khoa);
  if (khoa) {
    $("lockErr").classList.add("hidden");
    setTimeout(() => $("lockPw").focus(), 30);
  } else {
    $("lockPw").value = "";
  }
  return khoa;
}
function moKhoa() {
  const pw = $("lockPw").value;
  if (!pw) { $("lockErr").textContent = "Chưa nhập mật khẩu."; $("lockErr").classList.remove("hidden"); return; }
  $("lockErr").classList.add("hidden");
  $("lockGo").disabled = true;
  $("lockGo").textContent = "Đang mở…";      // scrypt cố ý chạy chậm, phải báo cho biết
  send({ cmd: "unlock", password: pw });
}
$("lockGo").onclick = moKhoa;
$("lockPw").addEventListener("keydown", (e) => { if (e.key === "Enter") moKhoa(); });
$("lockImport").onclick = () => {
  if (!$("lockPw").value) {
    $("lockErr").textContent = "Gõ mật khẩu của tài khoản đó vào ô trên trước đã.";
    $("lockErr").classList.remove("hidden");
    return;
  }
  $("lockImportFile").click();
};
$("lockImportFile").addEventListener("change", async (e) => {
  const f = e.target.files[0]; e.target.value = "";
  if (!f) return;
  let data;
  try { data = JSON.parse(await f.text()); }
  catch { $("lockErr").textContent = "Tệp hỏng hoặc không phải tệp tài khoản."; $("lockErr").classList.remove("hidden"); return; }
  send({ cmd: "import_account", data, password: $("lockPw").value });
});

function renderAccount() {
  const co = !!myState?.has_account;
  $("accountNo").classList.toggle("hidden", co);
  $("accountYes").classList.toggle("hidden", !co);
  $("accountNote").innerHTML = co
    ? "Máy này <b>có mật khẩu</b>. Khóa bí mật và khóa mở kho tin nhắn được bọc bằng "
      + "mật khẩu (scrypt → AES-256-GCM), nên chép tệp sang máy khác cũng vô dụng nếu "
      + "không biết mật khẩu."
    : "Chưa đặt mật khẩu. Khóa bí mật hiện chỉ được Windows bảo vệ theo tài khoản đăng nhập — "
      + "ai vào được máy này bằng tài khoản của bạn là dùng được Sentinell.";
}

$("accCreate").onclick = async () => {
  const r = await hoiMatKhau({
    tieuDe: "🔒 Đặt mật khẩu cho máy này",
    moTa: "Từ lần mở app sau, phải nhập mật khẩu này mới dùng được. Quên mật khẩu là "
      + "mất luôn khóa danh tính và toàn bộ tin nhắn đã lưu — không ai khôi phục hộ được. "
      + "Tối thiểu 8 ký tự.",
  });
  if (r) send({ cmd: "create_account", password: r.moi });
};
$("accChange").onclick = async () => {
  const r = await hoiMatKhau({
    tieuDe: "Đổi mật khẩu", moTa: "Nhập mật khẩu hiện tại, rồi mật khẩu mới.", coCu: true,
  });
  if (r) send({ cmd: "change_password", old_password: r.cu, password: r.moi });
};
$("accRemove").onclick = async () => {
  const r = await hoiMatKhau({
    tieuDe: "Bỏ mật khẩu",
    moTa: "Khóa sẽ quay lại chế độ chỉ được Windows bảo vệ theo tài khoản đăng nhập.",
    coNhacLai: false, nutOk: "Bỏ mật khẩu",
  });
  if (r) send({ cmd: "remove_account", password: r.moi });
};
$("accLock").onclick = () => send({ cmd: "lock" });

// ================================================================ sự kiện node
function handleEvent(m) {
  switch (m.type) {
    case "state":
      myState = m;
      if (renderLock(m)) return;     // còn khóa thì không có gì để vẽ
      renderState();
      break;
    case "unlock_fail":
      $("lockGo").disabled = false;
      $("lockGo").textContent = "Mở khóa";
      $("lockErr").textContent = m.text || "Mở khóa thất bại.";
      $("lockErr").classList.remove("hidden");
      break;
    case "unlocked":
      $("lockGo").disabled = false;
      $("lockGo").textContent = "Mở khóa";
      break;
    case "account_file":
      downloadJson("sentinell-tai-khoan.sen", m.data);
      sysMessage("Đã lưu tệp tài khoản. Giữ kỹ — nhưng kể cả lộ tệp thì vẫn cần mật khẩu mới mở được.");
      break;
    case "peers": peers = m.peers; renderPeers(); break;
    case "log": addLog(m); break;
    case "notice": sysMessage(m.text, m.bad); break;
    case "connected": openChat(m.connection); noteConnectedInModal(m.connection); break;
    case "disconnected": closeChat(m.reason); break;
    case "message": addMessage(m.direction, m.body, m.ts); notePreview(m); break;
    case "history": renderHistory(m.items); break;
    case "approval_request": showApproval(m); break;
    case "approval_done": hideApproval(); break;
    case "file_progress": showXfer(m); break;
    // Kết quả về sau khi đã gõ tiếp thì bỏ qua, kẻo kết quả cũ đè lên kết quả mới.
    case "search_results":
      if (m.q === timKiem.trim()) { ketQuaTin = m; veKetQua(locLienHe(m.q), m); }
      break;
  }
}

// ================================================================ tab bên trái
function selectTab(tab) {
  activeTab = tab;
  for (const b of document.querySelectorAll(".rail-btn[data-tab]")) {
    b.classList.toggle("on", b.dataset.tab === tab);
  }
  for (const p of document.querySelectorAll(".pane[data-pane]")) {
    p.classList.toggle("hidden", p.dataset.pane !== tab);
  }
  $("sideTitle").textContent =
    { chats: "Trò chuyện", lan: "Thiết bị cùng mạng", keys: "Khóa & bảo mật", logs: "Nhật ký hoạt động" }[tab];
  $("newChatBtn").classList.toggle("hidden", tab !== "chats");
  $("searchBar").classList.toggle("hidden", tab !== "chats");
  if (tab === "lan") $("lanDot").classList.add("hidden");   // đã xem thì tắt chấm báo
}
for (const b of document.querySelectorAll(".rail-btn[data-tab]")) {
  b.onclick = () => selectTab(b.dataset.tab);
}

// ================================================================ hiển thị trạng thái
function renderState() {
  const id = myState.identity;
  $("nameBadge").textContent = id.name;
  $("myFp").textContent = id.fp;
  $("nameInput").value = id.name;
  $("strictMode").checked = !!myState.strict_mode;
  paintAvatar($("meAvatar"), id.name, id.fp);
  renderPeers();
  renderContacts();
  renderAccount();
  veRaMang();
  renderConversations();
  renderTrashEntry();
  if (!$("trashModal").classList.contains("hidden")) renderTrashList();
  renderConnection(myState.connection);
  // Đang tìm mà DANH BẠ vừa đổi (đổi tên, xóa cuộc trò chuyện) thì phải hỏi lại node:
  // xóa cuộc trò chuyện là xóa luôn tin nhắn, giữ kết quả cũ thì bấm vào chỗ trống.
  // Còn state đẩy về vì lý do khác (thấy thêm thiết bị trên LAN…) thì chỉ vẽ lại.
  const q = timKiem.trim();
  if (!q) return;
  const chuKy = (myState.contacts || []).map((c) => `${c.fingerprint}:${c.name}:${c.pinned}`).join("|");
  if (chuKy !== chuKyDanhBa) { chuKyDanhBa = chuKy; chayTim(); }
  else veKetQua(locLienHe(q), ketQuaTin);
}

/** Avatar: chữ đầu lấy từ tên, màu lấy từ vân tay khóa — cùng khóa thì luôn cùng màu. */
function paintAvatar(el, name, fp) {
  el.textContent = initials(name);
  const hue = fp ? (parseInt(fp.slice(0, 4), 16) % 360) : 150;
  el.style.background = `hsl(${hue} 62% 62%)`;
  el.style.color = "#0d1a14";
}
function initials(name) {
  const parts = String(name || "?").trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2);
  return (parts[0][0] + parts[parts.length - 1][0]);
}

// ---------------------------------------------------------------- LAN
function renderPeers() {
  peers = (myState && !peers.length && myState.peers) ? myState.peers : peers;
  const list = $("peerList");
  const rows = peers || [];
  if (!rows.length) {
    list.innerHTML = '<p class="pane-note">Đang dò tìm… Hãy mở Sentinell trên thiết bị kia,'
      + ' và đảm bảo hai máy cùng một mạng WiFi.</p>';
    return;
  }
  if (activeTab !== "lan") $("lanDot").classList.remove("hidden");
  list.innerHTML = "";
  for (const p of rows) {
    const pinned = isPinned(p.fp);
    const row = document.createElement("div");
    row.className = "list-row";
    const av = document.createElement("span");
    av.className = "avatar sm";
    paintAvatar(av, p.name, p.fp);
    const mid = document.createElement("div");
    mid.style.minWidth = "0";
    mid.innerHTML = `<div class="nm">${esc(p.name)}
        <span class="pill ${pinned ? "ok" : ""}">${pinned ? "đã ghim ✓" : "chưa ghim"}</span></div>
      <div class="sub">${esc(p.host)}:${p.port}</div>`;
    const btn = document.createElement("button");
    btn.className = "btn sm"; btn.textContent = "Kết nối";
    btn.onclick = () => connectToPeer(p);
    row.append(av, mid, btn);
    list.appendChild(row);
  }
}

// ---------------------------------------------------------------- liên hệ đã ghim
function renderContacts() {
  const list = $("contactList");
  // CHỈ khóa đã ghim qua QR. `myState.contacts` nay là mọi cuộc trò chuyện (kể cả
  // chưa ghim) — để lọt vào đây là nói dối người dùng rằng một khóa chưa xác minh
  // đã được xác minh, đúng cái mà khối này sinh ra để chặn.
  const cs = daGhim();
  if (!cs.length) { list.innerHTML = '<p class="pane-note">Chưa ghim khóa nào.</p>'; return; }
  list.innerHTML = "";
  for (const c of cs) {
    const row = document.createElement("div");
    row.className = "list-row";
    const av = document.createElement("span");
    av.className = "avatar sm";
    paintAvatar(av, c.name, c.fingerprint);
    const mid = document.createElement("div");
    mid.style.minWidth = "0";
    // Không có cổng lắng nghe = thiết bị vào bằng trình duyệt, không gọi sang được.
    const diaChi = c.host && c.port ? ` · ${esc(c.host)}:${c.port}`
      : (c.host ? ` · ${esc(c.host)} (không nhận cuộc gọi đến)` : "");
    mid.innerHTML = `<div class="nm">${esc(c.name)}</div>
      <div class="sub">${esc(c.fingerprint)}${diaChi}</div>`;
    const btn = document.createElement("button");
    btn.className = "btn ghost sm"; btn.textContent = "Nhắn lại";
    btn.onclick = () => messageContact(c);
    row.append(av, mid, btn);
    list.appendChild(row);
  }
}

// ---------------------------------------------------------------- danh sách trò chuyện
function notePreview(m) {
  const fp = myState?.connection?.peer_fp;
  if (!fp) return;
  const body = m.body || {};
  const text = body.type === "file"
    ? ((body.mime || "").startsWith("image/") ? "📷 Ảnh" : `📎 ${body.name || "Tệp"}`)
    : String(body.text || "");
  previews[fp] = { preview: text, ts: m.ts, direction: m.direction };
  renderConversations();
}

// ================================================================ tìm kiếm
/** Bỏ dấu + hạ chữ thường — PHẢI khớp với Storage.khongDau() ở node, nếu không thì
 *  node tìm ra kết quả mà giao diện lại không tô được chỗ khớp. */
function khongDau(s) {
  return String(s ?? "")
    .normalize("NFD").replace(/[̀-ͯ]/g, "")
    .replace(/đ/g, "d").replace(/Đ/g, "D")
    .toLowerCase();
}

let timHen = null;
$("searchInput").addEventListener("input", (e) => {
  timKiem = e.target.value;
  $("searchClear").classList.toggle("hidden", !timKiem);
  clearTimeout(timHen);
  // Chờ người dùng ngừng gõ: mỗi lần tìm là giải mã hàng loạt dòng, gõ nhanh mà
  // bắn từng phím thì phí công vô ích.
  timHen = setTimeout(chayTim, 180);
});
$("searchInput").addEventListener("keydown", (e) => { if (e.key === "Escape") xoaTim(); });
$("searchClear").onclick = () => xoaTim();

function xoaTim() {
  timKiem = "";
  $("searchInput").value = "";
  $("searchClear").classList.add("hidden");
  chayTim();
  $("searchInput").blur();
}

function chayTim() {
  const q = timKiem.trim();
  const hien = q.length > 0;
  $("searchResults").classList.toggle("hidden", !hien);
  $("convList").classList.toggle("hidden", hien);
  $("convEmpty").classList.toggle("hidden", hien || (myState?.contacts || []).length > 0);
  renderTrashEntry();
  ketQuaTin = null;
  if (!hien) { $("searchResults").innerHTML = ""; return; }
  // Lọc tên liên hệ ngay tại chỗ (không cần hỏi node), còn nội dung tin nhắn thì
  // phải nhờ node vì chỉ nó mới giải mã được kho.
  veKetQua(locLienHe(q), null);
  send({ cmd: "search", q });
}

function locLienHe(q) {
  const k = khongDau(q);
  return (myState?.contacts || []).filter((c) => khongDau(c.name).includes(k));
}

/** Tô đậm chỗ khớp. Dò trên chuỗi đã bỏ dấu nhưng CẮT trên chuỗi gốc, để chữ hiện ra
 *  vẫn còn nguyên dấu. Độ dài hai chuỗi lệch nhau thì thôi không tô (khỏi cắt nhầm). */
function toKhop(goc, q) {
  const chuan = khongDau(goc), k = khongDau(q).trim();
  if (!k || chuan.length !== goc.length) return esc(goc);
  let ra = "", tu = 0, vt;
  while ((vt = chuan.indexOf(k, tu)) >= 0) {
    ra += esc(goc.slice(tu, vt)) + "<mark>" + esc(goc.slice(vt, vt + k.length)) + "</mark>";
    tu = vt + k.length;
  }
  return ra + esc(goc.slice(tu));
}

function veKetQua(lienHe, tin) {
  const box = $("searchResults");
  const q = timKiem.trim();
  box.innerHTML = "";

  if (lienHe.length) {
    box.insertAdjacentHTML("beforeend", '<div class="sr-head">Cuộc trò chuyện</div>');
    for (const c of lienHe) {
      const b = document.createElement("button");
      b.className = "sr-item";
      const av = document.createElement("span");
      av.className = "avatar sm";
      paintAvatar(av, c.name, c.fingerprint);
      const mid = document.createElement("div");
      mid.style.minWidth = "0";
      mid.innerHTML = `<div class="sr-top"><span class="sr-who">${toKhop(c.name, q)}</span></div>`
        + `<div class="sr-text">${esc(c.last?.preview || "chưa có tin nhắn")}</div>`;
      b.append(av, mid);
      b.onclick = () => moCuocTroChuyen(c, null);
      box.appendChild(b);
    }
  }

  if (tin === null) {
    box.insertAdjacentHTML("beforeend", '<div class="sr-head">Tin nhắn</div><div class="sr-none">Đang tìm…</div>');
    return;
  }
  box.insertAdjacentHTML("beforeend", '<div class="sr-head">Tin nhắn</div>');
  if (!tin.items.length) {
    box.insertAdjacentHTML("beforeend",
      `<div class="sr-none">Không có tin nhắn nào chứa “${esc(q)}”.</div>`);
    if (!lienHe.length) {
      box.insertAdjacentHTML("beforeend",
        '<div class="sr-none">Chỉ tìm được trong lịch sử đã lưu trên máy này. '
        + 'Tin nhắn trao đổi ở chế độ web trên điện thoại không được lưu nên không tìm ra.</div>');
    }
    return;
  }
  for (const m of tin.items) {
    const b = document.createElement("button");
    b.className = "sr-item";
    const av = document.createElement("span");
    av.className = "avatar sm";
    paintAvatar(av, m.peer_name, m.peer_fp);
    const nhan = m.kind === "file"
      ? ((m.mime || "").startsWith("image/") ? "📷 " : "📎 ")
      : (m.direction === "out" ? "Bạn: " : "");
    const mid = document.createElement("div");
    mid.style.minWidth = "0";
    mid.innerHTML = `<div class="sr-top"><span class="sr-who">${esc(m.peer_name)}</span>`
      + `<span class="sr-when">${fmtWhen(m.ts)}</span></div>`
      + `<div class="sr-text">${esc(nhan)}${toKhop(m.text, q)}</div>`;
    b.append(av, mid);
    b.onclick = () => moCuocTroChuyen(
      { pub: m.peer_pub, fingerprint: m.peer_fp, name: m.peer_name }, m.ts);
    box.appendChild(b);
  }
  if (tin.truncated) {
    box.insertAdjacentHTML("beforeend",
      '<div class="sr-none">Còn nữa — gõ thêm chữ để thu hẹp kết quả.</div>');
  }
}

/** Mở một cuộc trò chuyện từ kết quả tìm kiếm.
 *  Đang kết nối với đúng người đó thì vào thẳng phòng chat; còn không thì mở chế độ
 *  XEM LẠI (chỉ đọc) — vì lịch sử nằm sẵn trên máy, không cần bắt tay mới đọc được. */
function moCuocTroChuyen(c, ts) {
  nhayToi = ts;
  const conn = myState?.connection;
  if (conn?.connected && conn.peer_fp === c.fingerprint) {
    xemLai = null;
    showChatPane();
    send({ cmd: "load_history", peer_pub: conn.peer_pub });
    return;
  }
  moXemLai(c);
}

function moXemLai(c) {
  xemLai = c;
  const day = myState?.contacts?.find((x) => x.fingerprint === c.fingerprint) || c;
  $("welcome").classList.add("hidden");
  $("chat").classList.remove("hidden");
  $("chat").classList.add("readonly");
  $("readonlyBar").classList.remove("hidden");
  $("readonlyText").textContent = `Chỉ xem lại lịch sử — chưa kết nối với ${day.name}.`;
  $("peerName").textContent = day.name;
  $("peerFp").textContent = c.fingerprint;
  paintAvatar($("peerAvatar"), day.name, c.fingerprint);
  $("safetyNum").textContent = "—";
  const tb = $("trustBadge");
  tb.textContent = "đang xem lại";
  tb.title = "Đang đọc lịch sử lưu trên máy này, chưa nối với thiết bị kia.";
  tb.className = "pill";
  showChatPane();
  send({ cmd: "load_history", peer_pub: c.pub });
}

function dongXemLai() {
  xemLai = null;
  nhayToi = null;
  $("chat").classList.remove("readonly");
  $("readonlyBar").classList.add("hidden");
  closeChat(null, true);
}
$("readonlyClose").onclick = () => dongXemLai();
$("readonlyConnect").onclick = () => {
  const c = xemLai;
  if (!c) return;
  const day = myState?.contacts?.find((x) => x.fingerprint === c.fingerprint);
  if (day) messageContact(day);
  else sysMessage("Chưa ghim khóa của thiết bị này nên không gọi sang được. Hãy quét mã QR của họ.", true);
};

/** Cuộn tới và nháy sáng bong bóng ứng với mốc thời gian `ts`. */
function nhayDenTin(ts) {
  const el = $("messages").querySelector(`.msg[data-ts="${CSS.escape(String(ts))}"]`);
  if (!el) return false;
  el.scrollIntoView({ block: "center", behavior: "smooth" });
  el.classList.remove("nhay");
  void el.offsetWidth;                 // ép trình duyệt chạy lại hoạt ảnh
  el.classList.add("nhay");
  setTimeout(() => el.classList.remove("nhay"), 2200);
  return true;
}

function renderConversations() {
  const list = $("convList");
  const conn = myState?.connection;
  const cs = [...(myState?.contacts || [])];

  // Đối phương đang kết nối nhưng chưa ghim khóa vẫn phải có mặt trong danh sách,
  // nếu không thì đang chat mà bên trái trống trơn.
  if (conn?.connected && !cs.some((c) => c.fingerprint === conn.peer_fp)) {
    cs.unshift({ fingerprint: conn.peer_fp, pub: conn.peer_pub, name: conn.peer_name, pinned: false });
  }

  for (const c of cs) {
    const p = previews[c.fingerprint] || c.last;
    c._prev = p ? (p.direction === "out" ? "Bạn: " : "") + p.preview : null;
    c._ts = p?.ts || c.last_seen || 0;
  }
  cs.sort((a, b) => (b._ts || 0) - (a._ts || 0));

  // Đang tìm kiếm thì cột này nhường chỗ cho danh sách kết quả.
  const dangTim = timKiem.trim().length > 0;
  $("convEmpty").classList.toggle("hidden", dangTim || cs.length > 0);
  list.classList.toggle("hidden", dangTim);
  list.innerHTML = "";
  for (const c of cs) {
    const on = conn?.connected && conn.peer_fp === c.fingerprint;

    const wrap = document.createElement("div");
    wrap.className = "conv-wrap";

    const del = document.createElement("button");
    del.className = "conv-del";
    del.title = `Xóa cuộc trò chuyện với ${c.name}`;
    del.innerHTML = '<span class="ic" aria-hidden="true">🗑</span>Xóa';
    del.onclick = (e) => { e.stopPropagation(); askDeleteChat(c); };

    const row = document.createElement("button");
    row.className = "conv" + (on ? " active" : "");
    const av = document.createElement("span");
    av.className = "avatar";
    paintAvatar(av, c.name, c.fingerprint);
    const mid = document.createElement("div");
    mid.className = "conv-mid";
    mid.innerHTML = `<span class="conv-name">${esc(c.name)}${c.pinned ? ' <span class="vr" title="Đã xác minh khóa qua QR">✓</span>' : ""}</span>
      <span class="conv-prev">${c._prev ? esc(c._prev) : (on ? "đang kết nối…" : "chưa có tin nhắn")}</span>`;
    const right = document.createElement("div");
    right.className = "conv-right";
    right.innerHTML = `<span class="conv-time">${c._ts ? fmtWhen(c._ts) : ""}</span>`;
    row.append(av, mid, right);
    row.onclick = () => {
      // Cờ "vừa kéo xong" phải xét ĐẦU TIÊN. Sau một cú vuốt, trình duyệt vẫn phát ra
      // một sự kiện click; nếu xét `open` trước thì chính cú click ảo đó đóng hàng lại
      // ngay lập tức — nhìn như vuốt xong tự bật về chỗ cũ.
      if (row.dataset.dragged) { delete row.dataset.dragged; return; }
      if (wrap.classList.contains("open")) { wrap.classList.remove("open"); return; }
      if (on) { showChatPane(); return; }
      // Không có địa chỉ để gọi (điện thoại dùng trình duyệt, hoặc kho từ bản cũ) thì
      // MỞ LẠI LỊCH SỬ chứ đừng chỉ báo lỗi — lịch sử nằm sẵn trên máy, đọc được ngay.
      if (c.host && c.port) messageContact(c); else moXemLai(c);
    };

    wrap.append(del, row);
    attachSwipe(wrap, row);
    list.appendChild(wrap);
  }
}

/** Vuốt (hoặc kéo chuột) hàng sang trái để lộ nút Xóa màu đỏ.
 *
 *  Nghe `pointermove`/`pointerup` trên WINDOW chứ không trên hàng: khi hàng trượt sang
 *  trái, con trỏ dễ rơi ra ngoài nó (hoặc đè lên chính nút Xóa), lúc đó sự kiện không
 *  còn tới hàng nữa và cử chỉ đứt giữa chừng. */
function attachSwipe(wrap, row) {
  const W = 92;
  let startX = 0, startY = 0, dx = 0, keo = false, daQuyet = false;

  row.addEventListener("pointerdown", (e) => {
    if (e.pointerType === "mouse" && e.button !== 0) return;
    startX = e.clientX; startY = e.clientY; dx = 0; keo = true; daQuyet = false;
    window.addEventListener("pointermove", diChuyen, { passive: false });
    window.addEventListener("pointerup", ketThuc);
    window.addEventListener("pointercancel", ketThuc);
  });

  function diChuyen(e) {
    if (!keo) return;
    const mx = e.clientX - startX, my = e.clientY - startY;
    if (!daQuyet) {
      if (Math.abs(mx) < 6 && Math.abs(my) < 6) return;
      // Nghiêng về chiều dọc thì nhường cho việc cuộn danh sách, không cướp cử chỉ.
      if (Math.abs(my) > Math.abs(mx)) { thaoDoi(); keo = false; return; }
      daQuyet = true;
      wrap.classList.add("dragging");
      for (const o of document.querySelectorAll(".conv-wrap.open")) {
        if (o !== wrap) o.classList.remove("open");
      }
    }
    // Chặn kéo-thả/bôi đen mặc định của trình duyệt, kẻo nó cướp con trỏ rồi
    // bắn `pointercancel` làm cử chỉ đứt nửa chừng.
    if (e.cancelable) e.preventDefault();
    const goc = wrap.classList.contains("open") ? -W : 0;
    dx = Math.max(-W - 24, Math.min(0, mx + goc));
    row.style.transform = `translateX(${dx}px)`;
  }

  function ketThuc() {
    thaoDoi();
    if (!keo) return;
    keo = false;
    wrap.classList.remove("dragging");
    row.style.transform = "";
    if (daQuyet) {
      wrap.classList.toggle("open", dx < -W / 2);
      row.dataset.dragged = "1";   // chặn cú click ảo phát sinh ngay sau khi kéo
      setTimeout(() => { delete row.dataset.dragged; }, 400);
    }
  }

  function thaoDoi() {
    window.removeEventListener("pointermove", diChuyen);
    window.removeEventListener("pointerup", ketThuc);
    window.removeEventListener("pointercancel", ketThuc);
  }
}

function askDeleteChat(c) {
  const ok = confirm(`Xóa cuộc trò chuyện với "${c.name}"?\n\n`
    + "• Cuộc trò chuyện chuyển vào mục 🗑 Đã xóa ở cuối danh sách.\n"
    + "• Từ lúc đó nó KHÔNG còn hiện ra khi tìm kiếm nữa.\n"
    + "• Trong mục đó bạn có thể khôi phục lại, hoặc xóa hẳn khỏi máy.\n\n"
    + "Tin nhắn ở máy bên kia không bị ảnh hưởng.");
  if (!ok) return;
  send({ cmd: "delete_chat", pub: c.pub, fp: c.fingerprint, name: c.name });
}

// ================================================================ mục Đã xóa
function renderTrashEntry() {
  const n = (myState?.trash || []).length;
  $("trashEntry").classList.toggle("hidden", n === 0 || !!timKiem.trim());
  $("trashCount").textContent = String(n);
  if (n === 0) $("trashModal").classList.add("hidden");
}
$("trashEntry").onclick = () => { renderTrashList(); $("trashModal").classList.remove("hidden"); };
$("trashClose").onclick = () => $("trashModal").classList.add("hidden");
$("trashModal").addEventListener("click", (e) => {
  if (e.target === $("trashModal")) $("trashModal").classList.add("hidden");
});

function renderTrashList() {
  const box = $("trashList");
  const ds = myState?.trash || [];
  box.innerHTML = "";
  if (!ds.length) {
    box.innerHTML = '<div class="trash-none">Không có gì trong mục này.</div>';
    return;
  }
  for (const t of ds) {
    const row = document.createElement("div");
    row.className = "trash-row";
    const av = document.createElement("span");
    av.className = "avatar sm";
    paintAvatar(av, t.name, t.fingerprint);
    const info = document.createElement("div");
    info.className = "trash-info";
    info.innerHTML = `<div class="trash-name">${esc(t.name)}</div>`
      + `<div class="trash-sub">${t.count} tin · xóa ${fmtWhen(t.deleted_at)}`
      + `${t.was_pinned ? " · đã ghim khóa" : ""}</div>`;

    const khoi = document.createElement("button");
    khoi.className = "btn ghost sm";
    khoi.textContent = "↩️ Khôi phục";
    khoi.onclick = () => send({ cmd: "restore_chat", fp: t.fingerprint });

    const han = document.createElement("button");
    han.className = "btn danger sm";
    han.textContent = "Xóa vĩnh viễn";
    han.onclick = () => {
      if (!confirm(`Xóa vĩnh viễn ${t.count} tin nhắn với "${t.name}"?\n\n`
        + "Sau bước này KHÔNG lấy lại được nữa.")) return;
      send({ cmd: "purge_chat", fp: t.fingerprint });
    };

    row.append(av, info, khoi, han);
    box.appendChild(row);
  }
}

// Bấm ra chỗ trống trong danh sách thì đóng hàng đang mở nút Xóa.
$("convList").addEventListener("click", (e) => {
  if (e.target.closest(".conv-wrap")) return;
  for (const o of document.querySelectorAll(".conv-wrap.open")) o.classList.remove("open");
});

// "Đã ghim" là khẳng định về BẢO MẬT (khóa này đã xác minh tận nơi qua QR), nên phải
// lọc theo c.pinned — `contacts` nay gồm cả thiết bị mới chỉ từng nói chuyện.
function daGhim() { return (myState?.contacts || []).filter((c) => c.pinned); }
function isPinned(fp) { return daGhim().some((c) => c.fingerprint === fp); }
function pinnedPubByFp(fp) {
  const c = daGhim().find((x) => x.fingerprint === fp);
  return c ? c.pub : null;
}

// ================================================================ kết nối peer
function connectToPeer(p) {
  const expect = pinnedPubByFp(p.fp); // chỉ tin khóa đã ghim qua QR
  if (!expect) {
    sysMessage(`Bạn chưa xác minh khóa của "${p.name}". Vẫn kết nối được, nhưng hãy quét mã QR `
      + "của họ để chắc chắn không phải kẻ mạo danh.");
  }
  // Nếu vừa quét QR của đúng thiết bị này thì gửi kèm bằng chứng để họ ghim ngược lại mình.
  const pc = (expect && scannedPairPub === expect) ? scannedPairCode : null;
  send({ cmd: "connect", host: p.host, port: p.port, expect_pub: expect, pair_code: pc });
}

/** Nhắn lại một liên hệ đã ghép đôi (dùng địa chỉ đã lưu).
 *
 *  Chỉ gọi sang được thiết bị nào TỰ LẮNG NGHE và đã khai báo cổng trong lúc bắt tay.
 *  Điện thoại vào bằng trang /join là một trang web trong trình duyệt — nó không mở
 *  cổng nào cả, nên không có gì để gọi tới. Trước đây ta cứ đoán bừa cổng 8000 rồi
 *  đâm vào "ECONNREFUSED"; giờ nói thẳng phải làm gì. */
function messageContact(c) {
  if (!c.host || !c.port) {
    sysMessage(`"${c.name}" không nhận được cuộc gọi đến (điện thoại dùng trình duyệt thì không mở cổng). `
      + "Hãy để thiết bị đó mở lại mã QR này và bấm Kết nối.", true);
    openKeyModal();
    return;
  }
  send({ cmd: "connect", host: c.host, port: c.port, expect_pub: c.pub, pair_code: null });
}

$("manualConnect").onclick = () => {
  const host = $("manualHost").value.trim();
  const port = parseInt($("manualPort").value, 10);
  if (host && port) send({ cmd: "connect", host, port, expect_pub: null });
};

// ================================================================ phòng chat
/** Màn hẹp: mở phòng chat thì ẩn danh sách đi (điều hướng kiểu app điện thoại). */
function showChatPane() { $("shell").classList.add("showing-chat"); }
function showListPane() { $("shell").classList.remove("showing-chat"); }
$("backBtn").onclick = () => showListPane();

function renderConnection(conn) {
  if (conn && conn.connected) { openChat(conn, true); return; }
  // Đang XEM LẠI lịch sử thì đừng đóng phòng chat: mỗi lần node đẩy `state` về mà
  // gọi closeChat() là người dùng bị hất ra khỏi thứ họ vừa mở từ kết quả tìm kiếm.
  if (xemLai) return;
  closeChat(null, true);
}
function openChat(conn, silent) {
  xemLai = null;
  $("chat").classList.remove("readonly");
  $("readonlyBar").classList.add("hidden");
  $("welcome").classList.add("hidden");
  $("chat").classList.remove("hidden");
  $("peerName").textContent = conn.peer_name || "?";
  $("peerFp").textContent = conn.peer_fp;
  paintAvatar($("peerAvatar"), conn.peer_name, conn.peer_fp);
  $("safetyNum").textContent = conn.safety || "—";
  const tb = $("trustBadge");
  if (conn.trusted) {
    tb.textContent = "đã xác minh ✓";
    tb.title = "Khóa của thiết bị này khớp với mã QR bạn đã quét — không phải kẻ mạo danh.";
    tb.className = "pill ok";
  } else {
    tb.textContent = "chưa xác minh";
    tb.title = "Chưa quét mã QR của thiết bị này. Tin nhắn vẫn được mã hóa, nhưng chưa chắc "
      + "bạn đang nói chuyện với đúng người. Hãy quét QR hoặc đối chiếu dãy số kiểm chứng.";
    tb.className = "pill warn";
  }
  setConn(true, "đang trò chuyện với " + (conn.peer_name || "?"));
  if (myState) myState.connection = conn;
  renderConversations();
  if (!silent) showChatPane();
  send({ cmd: "load_history", peer_pub: conn.peer_pub });
}
function closeChat(reason, silent) {
  $("chat").classList.add("hidden");
  $("welcome").classList.remove("hidden");
  $("messages").innerHTML = "";
  lastMsgMeta = null;
  showListPane();
  if (myState) myState.connection = null;
  renderConversations();
  if (reason && !silent) sysMessage(reason, true);
  if (!silent) setConn(true, "sẵn sàng");
}
$("disconnectBtn").onclick = () => send({ cmd: "disconnect" });

// ---- bảng bảo mật ----
$("safetyToggle").onclick = () => {
  const on = $("shell").classList.toggle("with-inspector");
  $("inspector").classList.toggle("hidden", !on);
  $("safetyToggle").classList.toggle("on", on);
};
$("inspClose").onclick = () => {
  $("shell").classList.remove("with-inspector");
  $("inspector").classList.add("hidden");
  $("safetyToggle").classList.remove("on");
};

// ---- soạn & gửi ----
function sendText() {
  const t = $("msgInput").value.trim();
  if (!t) return;
  send({ cmd: "send_text", text: t });
  $("msgInput").value = "";
}
$("sendBtn").onclick = sendText;
$("msgInput").addEventListener("keydown", (e) => { if (e.key === "Enter") sendText(); });
const TOI_DA_TEP = 200 * 1024 * 1024;   // 200 MB — trên mức này thì gộp cả tệp trong RAM là dại

// ---- dải tiến độ truyền tệp ----
let xferTimer = null;
function showXfer(m) {
  const pct = m.total ? Math.round((m.done / m.total) * 100) : 0;
  $("xferLabel").textContent = (m.dir === "out" ? "Đang gửi " : "Đang nhận ") + m.name;
  $("xferFill").style.width = pct + "%";
  $("xferPct").textContent = pct + "%";
  $("xfer").classList.remove("hidden");
  // Giữ lại một nhịp khi xong để người dùng kịp thấy 100%, rồi mới ẩn đi.
  clearTimeout(xferTimer);
  xferTimer = setTimeout(() => $("xfer").classList.add("hidden"), pct >= 100 ? 900 : 8000);
}

$("attachBtn").onclick = () => $("fileInput").click();
$("fileInput").addEventListener("change", async (e) => {
  const f = e.target.files[0]; e.target.value = "";
  if (!f) return;
  if (f.size > TOI_DA_TEP) {
    sysMessage(`Tệp "${f.name}" nặng ${fmtSize(f.size)} — vượt mức 200 MB mà Sentinell gửi được một lần. `
      + "Hãy nén/chia nhỏ rồi gửi lại.", true);
    return;
  }
  const bytes = new Uint8Array(await f.arrayBuffer());
  sendFileFrame({ cmd: "send_file", name: f.name, mime: f.type || "application/octet-stream" }, bytes);
});

// ---- vẽ tin nhắn ----
function renderHistory(items) {
  $("messages").innerHTML = "";
  lastMsgMeta = null;
  for (const it of items) addMessage(it.direction, it.body, it.ts);
  // Đến từ kết quả tìm kiếm: nhảy tới đúng bong bóng đó.
  if (nhayToi !== null && nhayToi !== undefined) {
    const dich = nhayToi;
    nhayToi = null;
    if (!nhayDenTin(dich)) {
      sysMessage("Tin nhắn đó nằm ngoài 200 tin gần nhất nên chưa nạp lên được.", false);
    }
  }
  // Lấy luôn tin cuối làm dòng xem trước bên trái — sau khi nạp lại trang thì
  // liên hệ chưa ghim không có sẵn `last` từ node, để trống nhìn rất cụt.
  const it = items[items.length - 1];
  if (it) notePreview({ direction: it.direction, body: it.body, ts: it.ts });
}

/** Gom cụm tin cùng người gửi trong vòng 5 phút, và chèn vạch ngăn khi sang ngày mới. */
function addMessage(direction, body, ts) {
  const box = $("messages");
  const me = direction === "out";

  if (!lastMsgMeta || !sameDay(lastMsgMeta.ts, ts)) {
    const sep = document.createElement("div");
    sep.className = "daysep";
    sep.textContent = fmtDay(ts);
    box.appendChild(sep);
    lastMsgMeta = null;               // sang ngày mới thì bắt đầu cụm mới
  }
  const grouped = lastMsgMeta && lastMsgMeta.direction === direction && (ts - lastMsgMeta.ts) < 300;

  let html;
  if (body.type === "file") {
    const integ = body.integrity ? "toàn vẹn ✓" : "❌ sai toàn vẹn";
    if ((body.mime || "").startsWith("image/")) {
      html = `📎 ${esc(body.name)}<img src="${esc(body.url)}" alt="ảnh đã nhận">`
        + `<div class="meta">${integ} · ${fmtTime(ts)}</div>`;
    } else {
      html = `📎 <a href="${esc(body.url)}" download="${esc(body.name)}">${esc(body.name)}</a>`
        + ` <span class="faint">(${fmtSize(body.size)})</span>`
        + `<div class="meta">${integ} · ${fmtTime(ts)}</div>`;
    }
  } else {
    html = esc(body.text) + `<div class="meta">${fmtTime(ts)}</div>`;
  }

  const el = document.createElement("div");
  el.className = "msg " + (me ? "me" : "them") + (grouped ? " grp" : "");
  el.dataset.ts = String(ts);           // để kết quả tìm kiếm nhảy đúng bong bóng này
  if (body.type === "file" && body.integrity === false) el.classList.add("bad-integrity");
  el.innerHTML = html;

  // bong bóng cuối cụm mới có "đuôi" — bong bóng trước đó mất đuôi đi
  const prev = box.lastElementChild;
  if (grouped && prev && prev.classList.contains("msg")) prev.classList.remove("tail");
  el.classList.add("tail");

  box.appendChild(el);
  box.scrollTop = box.scrollHeight;
  lastMsgMeta = { direction, ts };
}

// ================================================================ thông báo
/** Toast ngắn + lưu vào "Nhật ký hoạt động" (không nối thẳng vào trang). */
function sysMessage(text, bad = false, kind = "") {
  showToast(text, bad ? "bad" : kind);
  addActivity(text, bad);
}
function showToast(text, kind = "") {
  const box = $("toasts");
  const t = document.createElement("div");
  t.className = "toast " + kind;
  t.textContent = text;
  box.appendChild(t);
  while (box.children.length > 3) box.removeChild(box.firstChild);
  setTimeout(() => { t.classList.add("leaving"); setTimeout(() => t.remove(), 260); }, 4500);
}
function addActivity(text, bad) {
  const box = $("activityLog");
  const row = document.createElement("div");
  row.className = "row-a" + (bad ? " bad" : "");
  row.innerHTML = `<span class="t">${fmtTime(Date.now() / 1000)}</span>${esc(text)}`;
  box.insertBefore(row, box.firstChild);
  while (box.children.length > 80) box.removeChild(box.lastChild);
}
function addLog(m) {
  const div = document.createElement("div");
  const cls = { "verify-ok": "ok", safety: "ok", derive: "ok",
                "verify-fail": "bad", "decrypt-fail": "bad", warn: "warn" }[m.step] || "";
  div.className = "entry " + cls;
  div.innerHTML = `<span class="tag">${esc(m.step)}</span> ${esc(m.detail)}`;
  const box = $("log");
  box.appendChild(div);
  while (box.children.length > 150) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}

// ================================================================ danh tính / khóa
$("saveName").onclick = () => send({ cmd: "set_name", name: $("nameInput").value });
$("showKeyBtn").onclick = () => openKeyModal();
$("keyClose").onclick = () => closeKeyModal();
$("newChatBtn").onclick = () => openKeyModal();
$("startPairBtn").onclick = () => openKeyModal();

function openKeyModal() {
  if (!myState) return;
  $("modalFp").textContent = myState.identity.fp;
  $("pairCodeText").textContent = myState.pair_code || "—";
  $("keyModal").classList.remove("hidden");
  // Rà mạng phải SỐNG: kẻ tấn công có thể chen vào ngay giữa lúc đang ghép đôi.
  clearInterval(raTimer);
  raTimer = setInterval(() => send({ cmd: "get_state" }), 4000);

  // MỘT mã duy nhất cho mọi thiết bị: URL /join mang sẵn khóa + mã ghép đôi + ĐỊA CHỈ.
  // Nhờ có địa chỉ, máy kia đọc mã xong là ghim khóa rồi VÀO CHAT LUÔN.
  fetch("/api/info").then((r) => r.json()).then((info) => {
    // Máy có nhiều card mạng (VirtualBox/WSL/VPN) thì cái đoán được chưa chắc là cái
    // điện thoại với tới được — cho chọn tay, mã QR vẽ lại ngay.
    const dsIp = (info.lan_ips && info.lan_ips.length ? info.lan_ips : [{ ip: info.lan_ip, iface: "" }]);
    const pick = $("addrPick");
    if (pick.options.length !== dsIp.length || pick.dataset.port !== String(info.port)) {
      pick.innerHTML = "";
      for (const d of dsIp) {
        const o = document.createElement("option");
        o.value = d.ip;
        o.textContent = d.iface ? `${d.ip}  (${d.iface})` : d.ip;
        pick.appendChild(o);
      }
      pick.dataset.port = String(info.port);
      pick.value = info.lan_ip;
    }
    const veLai = () => {
      const ip = pick.value || info.lan_ip;
      const url = `http://${ip}:${info.port}/join#k=${info.pub}`
        + `&n=${encodeURIComponent(info.name)}&pc=${encodeURIComponent(myState.pair_code || "")}`;
      drawQr($("myKeyQr"), url, 6);
      inviteUrl = url;
      $("keyText").value = url;
      $("selfAddr").textContent = `${ip}:${info.port}`;

      // Nhãn an toàn của đúng đường đang chia sẻ.
      const d = dsIp.find((x) => x.ip === ip) || {};
      const an = d.an || "thap";
      $("netBadge").textContent = d.nhan || "Chưa rõ";
      $("netBadge").className = "pill an-" + an;
      $("netNote").className = "net-note an-" + an;
      // Điểm phát sóng chạy được CẢ HAI CHIỀU — phải nêu cả hai, vì rất nhiều máy không
      // phát được (không có card WiFi phát được, hoặc đang nối bằng dây), và iPhone thì
      // chưa có app riêng nên buộc phải dùng chế độ web.
      const CACH_LAM = "<br><b>Cách nối trực tiếp — chọn một trong ba:</b>"
        + "<br>• <b>Máy tính phát:</b> Cài đặt → Mạng → Điểm phát sóng di động → cho điện thoại "
        + "nối vào → chọn <code class=\"mono\">192.168.137.x</code> ở trên."
        + "<br>• <b>Điện thoại phát qua WiFi</b> (khi máy tính không phát được): bật Điểm truy cập "
        + "cá nhân → cho <b>máy tính</b> nối vào → chọn <code class=\"mono\">172.20.10.x</code> "
        + "(iPhone) hoặc <code class=\"mono\">192.168.43.x</code> (Android)."
        + "<br>• <b>Cắm cáp USB</b> (khi máy tính KHÔNG CÓ card WiFi): cắm điện thoại vào máy "
        + "bằng cáp → bật Điểm truy cập cá nhân → máy tính hiện thêm một card mạng mang địa chỉ "
        + "<code class=\"mono\">172.20.10.x</code>. Đây là đường an toàn nhất: chỉ có sợi cáp, "
        + "không sóng, không ai chen vào được.";

      // Máy đang CÓ SẴN một đường trực tiếp mà lại đang chọn đường kém an toàn hơn —
      // nói thẳng ra, đừng để người dùng tự mò trong danh sách.
      const coSan = dsIp.find((x) => x.an === "cao" && x.ip !== ip);
      const GOI_Y = coSan
        ? `<br><b>👉 Máy này đang có sẵn đường nối trực tiếp:</b> chọn <code class="mono">${esc(coSan.ip)}</code>`
          + ` (${esc(coSan.iface || "")}) ở ô trên là xong.`
        : "";

      $("netNote").innerHTML = (an === "cao" ? "✅ " : an === "vua" ? "⚠️ " : "🚫 ")
        + esc(d.y || "Chưa xác định được loại mạng.")
        + (an === "cao" ? "" : GOI_Y + CACH_LAM);

      // Mạng công cộng: bắt xác nhận rõ ràng rồi mới đưa mã QR ra. Không chặn hẳn —
      // có lúc người dùng không còn lựa chọn nào khác — nhưng không để họ làm mà không biết.
      const batXacNhan = an === "thap";
      $("netAck").classList.toggle("hidden", !batXacNhan);
      if (batXacNhan) $("netAckBox").checked = false;
      capNhatCheQr();

      // Báo node biết đang chia sẻ qua đường nào — chỉ mạng con đó tải được mã của
      // chế độ web, mạng khác bị chặn thẳng.
      send({ cmd: "set_web_addr", ip });
      veRaMang();
    };
    pick.onchange = veLai;
    veLai();
  }).catch(() => { inviteUrl = ""; $("keyText").value = "(không lấy được địa chỉ LAN)"; });
}

/** Kết quả rà mạng — vẽ lại mỗi lần node đẩy state về, nên nó cập nhật ngay trong lúc
 *  cửa sổ QR đang mở, trước khi người dùng kịp nhắn gì.
 *
 *  KHÔNG hứa quá: chỉ bắt được kiểu tấn công hay gặp nhất (giả mạo ARP) và chuyện có thêm
 *  thiết bị lạ tải trang. "Chưa thấy gì" KHÔNG đồng nghĩa với "chắc chắn an toàn" — nói
 *  ngược lại là còn tệ hơn không rà. */
function veRaMang() {
  const el = $("scanLine");
  if (!el || $("keyModal").classList.contains("hidden")) return;
  const r = myState?.ra_mang;
  const ai = myState?.web_fetchers || [];
  const canh = [];

  if (r?.nghiNgo) canh.push(...r.dauHieu.map(esc));
  if (ai.length > 1) {
    canh.push(`<b>${ai.length} thiết bị</b> đã tải trang này trong lượt ghép đôi này `
      + `(${ai.map((x) => esc(x.ip)).join(", ")}). Nếu bạn chỉ dùng một điện thoại thì `
      + "hãy ngắt ngay và đổi sang nối trực tiếp.");
  }

  el.className = "scan-line" + (canh.length ? " xau" : "");
  if (canh.length) {
    el.innerHTML = "🚨 <b>Phát hiện dấu hiệu bất thường trong mạng:</b><br>• " + canh.join("<br>• ");
    return;
  }
  const daTai = ai.length === 1 ? ` · 1 thiết bị đã tải trang (${esc(ai[0].ip)})` : "";
  el.innerHTML = r?.xong
    ? `🔍 Rà mạng: chưa thấy dấu hiệu giả mạo (${r.soLangGieng} thiết bị lân cận)${daTai}. `
      + "<span class=\"faint\">Chỉ bắt được kiểu tấn công phổ biến nhất — không thấy gì không có nghĩa là chắc chắn an toàn.</span>"
    : "🔍 Đang rà mạng…";
}

/** Che mã QR cho tới khi người dùng xác nhận đã hiểu rủi ro của mạng công cộng. */
function capNhatCheQr() {
  const can = !$("netAck").classList.contains("hidden");
  const che = can && !$("netAckBox").checked;
  $("myKeyQr").classList.toggle("hidden", che);
  $("qrActions").classList.toggle("hidden", che);
  $("qrHidden").classList.toggle("hidden", !che);
}
$("netAckBox").onchange = capNhatCheQr;

/** Đóng cửa sổ khóa/QR. */
function closeKeyModal() {
  clearInterval(modalTimer); modalTimer = null;
  clearInterval(raTimer); raTimer = null;
  $("keyModal").classList.add("hidden");
  $("modalConnected").classList.add("hidden");
}

/** Bên kia quét xong và bắt tay thành công → báo ngay trong cửa sổ QR rồi tự đóng
 *  để lộ ra khung chat, thay vì đứng che màn hình. */
function noteConnectedInModal(conn) {
  if ($("keyModal").classList.contains("hidden")) return;
  const b = $("modalConnected");
  b.classList.remove("hidden");
  let left = 4;
  const tick = () => { b.textContent = `✅ Đã kết nối với "${conn.peer_name || "?"}" — mở khung chat sau ${left}s…`; };
  tick();
  clearInterval(modalTimer);
  modalTimer = setInterval(() => {
    left -= 1;
    if (left <= 0) { closeKeyModal(); return; }
    tick();
  }, 1000);
}

// Mọi cửa sổ đều đóng được bằng Esc hoặc bấm ra nền — để không bao giờ bị kẹt cứng.
// Riêng hộp DUYỆT kết nối cố ý KHÔNG cho đóng kiểu này: chấp nhận hay từ chối một
// thiết bị lạ phải là lựa chọn có ý thức, không được lỡ tay Esc mà cho qua.
function closeTopModal() {
  if (!$("scanModal").classList.contains("hidden")) return closeScan();
  if (!$("keyModal").classList.contains("hidden")) return closeKeyModal();
}
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeTopModal(); });
for (const id of ["keyModal", "scanModal"]) {
  $(id).addEventListener("click", (e) => { if (e.target.id === id) closeTopModal(); });
}

$("rotateBtn").onclick = () => {
  if (confirm("Xoay khóa sẽ tạo danh tính mới; các liên hệ phải quét lại QR của bạn. Tiếp tục?")) {
    send({ cmd: "rotate_key" });
    setTimeout(openKeyModal, 300);
  }
};

// ---- duyệt kết nối đến ----
let apTimer = null;
function showApproval(m) {
  $("apName").textContent = m.name || "?";
  $("apFp").textContent = "vân tay: " + m.fp;
  $("apHost").textContent = m.host ? "địa chỉ: " + m.host : "";
  const pinned = isPinned(m.fp);
  const badge = $("apPinned");
  badge.textContent = pinned ? "đã ghim khóa ✓" : "chưa ghim khóa — người lạ";
  badge.className = "pill " + (pinned ? "ok" : "warn");
  $("approveModal").classList.remove("hidden");
  let left = 60;
  clearInterval(apTimer);
  $("apCountdown").textContent = `tự từ chối sau ${left}s`;
  apTimer = setInterval(() => {
    left -= 1;
    $("apCountdown").textContent = `tự từ chối sau ${left}s`;
    if (left <= 0) clearInterval(apTimer);
  }, 1000);
}
function hideApproval() {
  clearInterval(apTimer);
  $("approveModal").classList.add("hidden");
}
$("apAccept").onclick = () => { send({ cmd: "approve_peer" }); hideApproval(); };
$("apReject").onclick = () => { send({ cmd: "reject_peer" }); hideApproval(); };
$("strictMode").onchange = (e) => send({ cmd: "set_strict", value: e.target.checked });

/** Vẽ QR ra canvas ở độ phân giải cao để tải về — nét hơn hẳn ảnh chụp màn hình. */
function qrToPngDataUrl(text, cell = 10, margin = 4) {
  const q = qrcode(0, "M");
  q.addData(text);
  q.make();
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

$("saveQrBtn").onclick = () => {
  if (!inviteUrl) { sysMessage("Chưa có liên kết để tạo mã.", true); return; }
  const a = document.createElement("a");
  a.href = qrToPngDataUrl(inviteUrl);
  a.download = `sentinell-qr-${myState.identity.fp.slice(0, 8)}.png`;
  a.click();
  sysMessage("Đã lưu ảnh QR. Gửi tệp này cho thiết bị kia, rồi ở đó bấm 📷 Quét QR → Chọn ảnh QR.",
    false, "good");
};
$("copyLinkBtn").onclick = () => {
  if (!inviteUrl) return;
  navigator.clipboard?.writeText(inviteUrl);
  sysMessage("Đã chép liên kết. Dán vào ô nhập ở thiết bị kia là xong — nó tự xác minh khóa và vào trò chuyện.",
    false, "good");
};
$("copyAddr").onclick = () => {
  const t = $("selfAddr").textContent;
  if (t && t !== "—") { navigator.clipboard?.writeText(t); sysMessage("Đã chép địa chỉ: " + t); }
};
$("newPairCodeBtn").onclick = () => { send({ cmd: "new_pair_code" }); setTimeout(openKeyModal, 250); };
// Sao lưu và mật khẩu nay là MỘT: tệp sao lưu luôn được mã hóa bằng mật khẩu.
// Máy đã đặt mật khẩu thì dùng luôn gói sẵn có; chưa đặt thì hỏi một mật khẩu
// riêng cho tệp này (không biến nó thành tài khoản của máy).
$("backupBtn").onclick = async () => {
  if (myState?.has_account) { send({ cmd: "export_account" }); return; }
  const r = await hoiMatKhau({
    tieuDe: "💾 Sao lưu / chuyển máy",
    moTa: "Máy này chưa đặt mật khẩu, nên hãy đặt một mật khẩu riêng để khóa tệp sao lưu. "
      + "Khóa bí mật của bạn nằm trong tệp đó — không mã hóa thì ai nhặt được tệp cũng "
      + "mạo danh được bạn. Tối thiểu 8 ký tự.",
  });
  if (r) send({ cmd: "export_account", password: r.moi });
};
$("restoreBtn").onclick = () => $("restoreFile").click();
$("restoreFile").addEventListener("change", async (e) => {
  const f = e.target.files[0]; e.target.value = "";
  if (!f) return;
  let data;
  try { data = JSON.parse(await f.text()); }
  catch { alert("Tệp không đọc được."); return; }

  if (data?.kind === "sentinell-account") {
    const r = await hoiMatKhau({
      tieuDe: "↩️ Phục hồi từ tệp",
      moTa: `Nhập mật khẩu của tệp sao lưu này (của "${data.name || "?"}"). `
        + "Danh tính hiện tại trên máy sẽ bị thay.",
      coNhacLai: false, nutOk: "Phục hồi",
    });
    if (r) send({ cmd: "import_file", data, password: r.moi });
    return;
  }
  if (!confirm("Tệp này là bản sao lưu đời cũ, KHÔNG được mã hóa — khóa bí mật nằm trong đó "
    + "ở dạng đọc được.\n\nVẫn phục hồi?")) return;
  send({ cmd: "import_file", data });
});

// ================================================================ quét QR
$("scanBtn").onclick = () => openScan();
$("scanClose").onclick = () => closeScan();
async function openScan() {
  $("scanModal").classList.remove("hidden");
  $("scanStatus").textContent = "Đang mở camera…";
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
    const v = $("scanVideo"); v.srcObject = scanStream; await v.play();
    $("scanStatus").textContent = "Đưa mã QR của thiết bị kia vào khung hình…";
    scanLoop();
  } catch (e) {
    $("scanStatus").innerHTML = "Không mở được camera (" + esc(e.message) + "). Dùng cách dán chuỗi / tải ảnh bên dưới.";
  }
}
function scanLoop() {
  const v = $("scanVideo"), c = $("scanCanvas");
  if (!v.videoWidth) { scanRAF = requestAnimationFrame(scanLoop); return; }
  c.width = v.videoWidth; c.height = v.videoHeight;
  const ctx = c.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(v, 0, 0, c.width, c.height);
  const img = ctx.getImageData(0, 0, c.width, c.height);
  let code = null;
  try { code = window.jsQR(img.data, img.width, img.height); } catch { /* jsQR có thể ném lỗi */ }
  if (code) { onScanned(code.data); return; }
  scanRAF = requestAnimationFrame(scanLoop);
}
function closeScan() {
  $("scanModal").classList.add("hidden");
  if (scanRAF) { cancelAnimationFrame(scanRAF); scanRAF = null; }
  if (scanStream) { scanStream.getTracks().forEach((t) => t.stop()); scanStream = null; }
  $("pasteKey").value = "";   // dọn sạch để lần mở sau không dính chuỗi cũ
}
function onScanned(text) { closeScan(); pinFromPayload(text); }

$("pinPasteBtn").onclick = () => pinFromPayload($("pasteKey").value.trim());
$("qrImageBtn").onclick = () => $("qrImageFile").click();
$("qrImageFile").addEventListener("change", async (e) => {
  const f = e.target.files[0]; e.target.value = "";
  if (!f) return;
  const img = new Image();
  img.onload = () => {
    const data = decodeQrFromImage(img);
    if (data) pinFromPayload(data);
    else sysMessage("Không đọc được mã QR trong ảnh này. Hãy dùng ảnh cắt sát vùng mã QR "
      + "(ảnh chụp cả màn hình thường quá nhỏ), hoặc dán chuỗi ở ô bên dưới.", true);
    URL.revokeObjectURL(img.src);
  };
  img.onerror = () => sysMessage("Không mở được tệp ảnh này.", true);
  img.src = URL.createObjectURL(f);
});

/** Ảnh chụp màn hình thường bị thu nhỏ/nén nên jsQR dễ trượt ở kích thước gốc.
 *  Thử lần lượt vài tỉ lệ (và cả ảnh đảo màu) trước khi kết luận là không đọc được. */
function decodeQrFromImage(img) {
  try { return _decodeQrFromImage(img); } catch { return null; }
}
function _decodeQrFromImage(img) {
  const c = $("scanCanvas");
  const ctx = c.getContext("2d", { willReadFrequently: true });
  const scales = [1, 0.75, 0.5, 1.5, 2, 0.35];
  const MAX_PX = 3_500_000;   // chặn ảnh quá lớn cho đỡ treo máy
  for (const sc of scales) {
    let w = Math.round(img.width * sc), h = Math.round(img.height * sc);
    if (w < 40 || h < 40) continue;
    if (w * h > MAX_PX) { const k = Math.sqrt(MAX_PX / (w * h)); w = Math.round(w * k); h = Math.round(h * k); }
    c.width = w; c.height = h;
    ctx.imageSmoothingEnabled = sc < 1;   // thu nhỏ thì làm mượt, phóng to thì giữ nét
    ctx.drawImage(img, 0, 0, w, h);
    const d = ctx.getImageData(0, 0, w, h);
    for (const inv of ["attemptBoth", "onlyInvert"]) {
      try {
        const code = window.jsQR(d.data, d.width, d.height, { inversionAttempts: inv });
        if (code && code.data) return code.data;
      } catch { /* jsQR có thể ném lỗi với ảnh lạ — bỏ qua, thử tỉ lệ khác */ }
    }
  }
  return null;
}

function pinFromPayload(text) {
  const r = parseQr(text);

  if (r.kind === "unknown") {
    // Đọc không ra thì GIỮ cửa sổ mở để thử ảnh khác ngay, khỏi phải mở lại từ đầu.
    sysMessage("Nội dung này không phải mã của Sentinell. Hãy kiểm tra lại ảnh hoặc chuỗi vừa dán.", true);
    return;
  }
  // Đọc được rồi thì đóng cửa sổ quét — dù mã đến từ camera, từ ảnh tải lên hay từ chuỗi dán.
  closeScan();

  if (r.kind === "address") {
    sysMessage(`Mã này chỉ có địa chỉ ${r.host}:${r.port}, không kèm khóa. Vẫn kết nối được `
      + "nhưng chưa xác minh được danh tính — hãy đối chiếu dãy số kiểm chứng sau khi vào.");
    send({ cmd: "connect", host: r.host, port: r.port, expect_pub: null });
    return;
  }

  // Có khóa: ghim lại (kèm địa chỉ nếu mã là lời mời)
  send({
    cmd: "pin_key", pub: r.pub, name: r.name || "",
    host: r.host || null, port: r.port || null, pair_code: r.pairCode || null,
  });
  if (r.pairCode) { scannedPairCode = r.pairCode; scannedPairPub = r.pub; }

  // Lời mời của máy tính, hoặc QR khóa của điện thoại bản Android (nay nó NGHE được nên mã
  // mang kèm địa chỉ h/p) → ghim xong gọi sang luôn.
  if ((r.kind === "invite" || r.kind === "key") && r.host && r.port) {
    sysMessage(`Đã ghim khóa của "${r.name || "thiết bị"}" — đang kết nối tới ${r.host}:${r.port}…`, false, "good");
    send({ cmd: "connect", host: r.host, port: r.port, expect_pub: r.pub, pair_code: r.pairCode || null });
  } else {
    const ten = r.name || "thiết bị này";
    sysMessage(`Đã ghim khóa của "${ten}". Mã này không kèm địa chỉ, nên hãy bấm Kết nối ở chính `
      + "thiết bị đó — hai bên sẽ tự ghim lẫn nhau, khỏi quét ngược lại.", false, "good");
  }
}

// ================================================================ tiện ích
// qrcode.js mặc định dùng bộ mã 'default' — nó CẮT MẤT mọi ký tự ngoài ASCII, nên mã QR
// chứa tiếng Việt (ví dụ tên "Điện thoại d85b") tạo ra vẫn quét được nhưng giải ra CHUỖI
// RỖNG. Phải chuyển sang UTF-8 ngay từ đầu. (Mã mời của máy tính thoát nạn chỉ vì tên đã
// được encodeURIComponent thành ASCII.)
if (typeof qrcode !== "undefined" && qrcode.stringToBytesFuncs && qrcode.stringToBytesFuncs["UTF-8"]) {
  qrcode.stringToBytes = qrcode.stringToBytesFuncs["UTF-8"];
}
function drawQr(container, text, cell = 4) {
  container.innerHTML = "";
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  container.innerHTML = qr.createImgTag(cell, 8);
}
function downloadJson(name, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name; a.click();
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtSize(n) {
  return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(2) + " MB";
}
function fmtTime(ts) {
  try { return new Date(ts * 1000).toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" }); }
  catch { return ""; }
}
function sameDay(a, b) {
  const x = new Date(a * 1000), y = new Date(b * 1000);
  return x.getFullYear() === y.getFullYear() && x.getMonth() === y.getMonth() && x.getDate() === y.getDate();
}
function fmtDay(ts) {
  const d = new Date(ts * 1000), now = new Date();
  const dayMs = 86400000;
  const strip = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((strip(now) - strip(d)) / dayMs);
  if (diff === 0) return "Hôm nay";
  if (diff === 1) return "Hôm qua";
  return d.toLocaleDateString("vi-VN", { day: "2-digit", month: "2-digit", year: "numeric" });
}
/** Cột phải của danh sách: hôm nay thì hiện giờ, cũ hơn thì hiện ngày. */
function fmtWhen(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000), now = new Date();
  if (sameDay(ts, now.getTime() / 1000)) return fmtTime(ts);
  const yesterday = (now.getTime() / 1000) - 86400;
  if (sameDay(ts, yesterday)) return "Hôm qua";
  return d.toLocaleDateString("vi-VN", { day: "2-digit", month: "2-digit" });
}

// Lấy địa chỉ LAN ngay từ đầu để hiện trong tab Khóa.
fetch("/api/info").then((r) => r.json()).then((info) => {
  $("selfAddr").textContent = `${info.lan_ip}:${info.port}`;
}).catch(() => { $("selfAddr").textContent = "(không xác định được)"; });

connectWS();
