// Kiểm logic phiên phía ĐIỆN THOẠI (mobile/src/transport.js — PeerLink) với một node DESKTOP
// THẬT (đúng lớp Node của app Electron, gọi sang bằng thư viện `ws`), qua máy chủ WebSocket tự
// viết của điện thoại (mobile/src/wsproto.js) trên socket TCP thật.
//
// Phần native (react-native-tcp-socket, NsdManager) phải kiểm trên máy ảo; còn TOÀN BỘ luồng
// giao thức — duyệt khóa lạ, giữ chữ ký tới sớm, ghép đôi hai chiều, chế độ chặt, bận, nhắn
// chữ và tệp hai chiều — kiểm được ở đây, nhanh và lặp lại được.
import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { genKeypair, newPairCode } from "@sentinell/core";
import { startServer } from "../desktop/server/index.js";
import { WsConn } from "../mobile/src/wsproto.js";
import { PeerLink, tuChoiBan } from "../mobile/src/transport.js";

let loi = 0;
const dat = (t, ok, x = "") => {
  console.log(`${t.padEnd(62, " ")} ${ok ? "OK" : "SAI"}${x ? "   " + x : ""}`);
  if (!ok) loi++;
};
const cho = (ms) => new Promise((r) => setTimeout(r, ms));
async function doiDen(dk, ms = 4000) {
  const t = Date.now();
  while (Date.now() - t < ms) { if (dk()) return true; await cho(25); }
  return false;
}

const goc = path.dirname(fileURLToPath(import.meta.url));
const thuMuc = fs.mkdtempSync(path.join(os.tmpdir(), "sentinell-phone-"));
const D = await startServer({ dataDir: path.join(thuMuc, "pc"), port: 8351, webDir: path.resolve(goc, "../web") });
const suPC = [];
D.node.uiClients.add({ send: (s) => suPC.push(JSON.parse(s)) });
const pc = (cmd) => D.node.handleUi(cmd);

// ------------------------------------------------------------------ "điện thoại"
const kp = genKeypair();
const dienThoai = { priv: kp.priv, pub: kp.pub, name: "Điện thoại thử", storage_key: "00".repeat(32) };
const danhBa = new Map();                 // pub -> liên hệ đã ghim trên điện thoại
let maQr = newPairCode();                 // mã ghép đôi đang hiện trên QR của điện thoại
let cheDoChat = false;
let phien = null;
const suDT = { approval: [], connected: [], msg: [], notice: [], closed: [] };

function taoPhien(extra = {}) {
  const p = new PeerLink({
    identity: dienThoai, activePairCode: maQr, listenPort: null,
    lookupContact: async (pub) => danhBa.get(pub) || null, strict: cheDoChat,
    ...extra,
    onApproval: (r) => { if (r) suDT.approval.push(r); },
    onConnected: (i) => suDT.connected.push(i),
    onMessage: (b) => suDT.msg.push(b),
    onNotice: (t) => suDT.notice.push(t),
    onDisconnected: (r) => suDT.closed.push(r),
  });
  phien = p;
  return p;
}

const mayChuDT = net.createServer((sock) => {
  const conn = new WsConn(sock, { heartbeatMs: 0 });
  conn.onopen = () => {
    if (phien && phien.busy) { tuChoiBan(conn); return; }   // đúng như App.js
    taoPhien().accept(conn);
  };
});
await new Promise((r) => mayChuDT.listen(0, "127.0.0.1", r));
const congDT = mayChuDT.address().port;

// ================================================================== 1. máy tính quét QR của điện thoại
console.log("--- máy tính quét QR điện thoại rồi GỌI SANG (điện thoại nghe, vai R) ---");
pc({ cmd: "pin_key", pub: dienThoai.pub, name: dienThoai.name, host: "127.0.0.1", port: congDT, pair_code: maQr });
pc({ cmd: "connect", host: "127.0.0.1", port: congDT, expect_pub: dienThoai.pub, pair_code: maQr });

dat("điện thoại hỏi duyệt khóa lạ (máy tính chưa có trong danh bạ)", await doiDen(() => suDT.approval.length === 1));
dat("hộp duyệt mang đúng tên máy tính", suDT.approval[0]?.name === D.node.storage.name);
dat("máy tính được báo 'đang chờ bên kia chấp nhận'", await doiDen(() => suPC.some((m) => m.type === "notice" && /Đang chờ thiết bị kia/.test(m.text))));
await cho(200);   // cho chữ ký của máy tính kịp tới SỚM — phải được giữ lại, không làm hỏng phiên
dat("chữ ký tới trước khi duyệt được giữ lại", !!phien._deferredSig);
phien.approve();

dat("điện thoại vào phòng sau khi bấm Chấp nhận", await doiDen(() => suDT.connected.length === 1));
const vao = suDT.connected[0] || {};
dat("điện thoại: máy tính đã chứng minh quét mã ⇒ ghép đôi hai chiều", vao.peerProvedPair === true && vao.trusted === true);
dat("máy tính: khóa điện thoại khớp khóa đã ghim ⇒ tin cậy", await doiDen(() => suPC.some((m) => m.type === "connected" && m.connection?.trusted)));
const ketNoiPC = suPC.find((m) => m.type === "connected")?.connection || {};
dat("safety number hai bên khớp", ketNoiPC.safety === phien.session.safety && !!ketNoiPC.safety);

pc({ cmd: "send_text", text: "Chào điện thoại, máy tính đây ✓" });
dat("điện thoại giải mã tin của máy tính", await doiDen(() => suDT.msg.some((m) => m.text === "Chào điện thoại, máy tính đây ✓")));
phien.sendText("Điện thoại đã nhận — trả lời từ vai R");
dat("máy tính giải mã tin của điện thoại", await doiDen(() => suPC.some((m) => m.type === "message" && m.direction === "in" && m.body?.text === "Điện thoại đã nhận — trả lời từ vai R")));

const anh = crypto.randomBytes(600 * 1024);   // 3 khối 256 KB, khung nhị phân
await pc({ cmd: "send_file", name: "anh.jpg", mime: "image/jpeg", data_b64: anh.toString("base64") });
dat("điện thoại nhận tệp 600 KB từ máy tính, SHA-256 khớp", await doiDen(() => suDT.msg.some((m) => m.type === "file" && m.name === "anh.jpg" && m.integrity === true && m.size === anh.length), 8000));

const tepDT = crypto.randomBytes(300 * 1024);
phien.sendFile({ base64: tepDT.toString("base64"), name: "tu-dien-thoai.bin", mime: "application/octet-stream" });
dat("máy tính nhận tệp 300 KB từ điện thoại", await doiDen(() => suPC.some((m) => m.type === "message" && m.direction === "in" && m.body?.type === "file" && m.body?.name?.includes("tu-dien-thoai")), 8000));

// ------------------------------------------------------------------ 2. đang bận
console.log("\n--- đang trong phiên thì người thứ ba bị báo bận ---");
{
  const { default: WebSocket } = await import("ws");
  const ws = new WebSocket(`ws://127.0.0.1:${congDT}/peer`);
  const tin = await new Promise((r) => { ws.on("message", (d) => r(String(d))); ws.on("close", () => r(null)); });
  dat("kết nối thứ hai nhận {type:'busy'}", tin && JSON.parse(tin).type === "busy");
  dat("phiên đang chạy không bị ảnh hưởng", phien.ready && !phien.closed);
}

pc({ cmd: "disconnect" });
dat("máy tính ngắt ⇒ điện thoại biết phiên đã đóng", await doiDen(() => suDT.closed.length >= 1));

// ================================================================== 3. chế độ chặt
console.log("\n--- chế độ chặt: khóa lạ bị từ chối thẳng, không hỏi ---");
{
  const kp2 = genKeypair();
  const lạ = { priv: kp2.priv, pub: kp2.pub, name: "Máy lạ" };
  cheDoChat = true;
  suDT.approval.length = 0;
  const truocDo = suDT.notice.length;
  // "máy lạ" gọi vào bằng PeerLink vai I (Node 22 có sẵn WebSocket toàn cục như React Native)
  const nhanCuaLa = [];
  const la = new PeerLink({ identity: lạ, onNotice: (t) => nhanCuaLa.push(t), onDisconnected: () => {} });
  la.connect("127.0.0.1", congDT);
  dat("bên gọi nhận lý do từ chối", await doiDen(() => nhanCuaLa.some((t) => /chỉ nhận kết nối từ liên hệ đã ghim/.test(t))));
  dat("điện thoại KHÔNG hiện hộp duyệt", suDT.approval.length === 0);
  dat("điện thoại ghi lại việc đã từ chối", suDT.notice.slice(truocDo).some((t) => /Đã từ chối/.test(t)));
  cheDoChat = false;
}

// ================================================================== 4. điện thoại GỌI máy tính (vai I)
console.log("\n--- điện thoại gọi máy tính (vai I), máy tính duyệt ---");
{
  await cho(300);
  suPC.length = 0;
  const truoc = suDT.connected.length;
  const p = taoPhien({ expectPub: D.node.storage.idPub });
  p.connect("127.0.0.1", D.port);
  dat("máy tính hỏi duyệt điện thoại", await doiDen(() => suPC.some((m) => m.type === "approval_request")) || await doiDen(() => suPC.some((m) => m.type === "connected")));
  if (suPC.some((m) => m.type === "approval_request")) pc({ cmd: "approve_peer" });
  dat("điện thoại vào phòng, khóa máy tính khớp khóa ghim", await doiDen(() => suDT.connected.length > truoc && suDT.connected.at(-1).trusted === true));
  p.sendText("chiều gọi đi vẫn chạy");
  dat("máy tính nhận tin của điện thoại", await doiDen(() => suPC.some((m) => m.type === "message" && m.body?.text === "chiều gọi đi vẫn chạy")));
  p.close();
}

// ================================================================== 5. khóa bị tráo
console.log("\n--- kẻ mạo danh: khóa không khớp khóa đã ghim ---");
{
  const kp3 = genKeypair();
  const giaMao = { priv: kp3.priv, pub: kp3.pub, name: dienThoai.name };   // cùng tên, khác khóa
  // máy tính đã ghim khóa THẬT của điện thoại; giờ "điện thoại giả" nghe ở cổng khác
  const giaSrv = net.createServer((sock) => {
    const conn = new WsConn(sock, { heartbeatMs: 0 });
    conn.onopen = () => new PeerLink({ identity: giaMao, lookupContact: async () => ({ pub: "x" }), onDisconnected: () => {} }).accept(conn);
  });
  await new Promise((r) => giaSrv.listen(0, "127.0.0.1", r));
  suPC.length = 0;
  pc({ cmd: "connect", host: "127.0.0.1", port: giaSrv.address().port, expect_pub: dienThoai.pub });
  dat("máy tính phát hiện khóa bị tráo và hủy", await doiDen(() => suPC.some((m) => m.type === "notice" && /Xác thực thất bại/.test(m.text))));
  dat("máy tính KHÔNG vào phòng với kẻ mạo danh", !suPC.some((m) => m.type === "connected"));
  giaSrv.close();
}

// ================================================================== 6. HAI ĐIỆN THOẠI (không có máy tính)
// Cả hai đầu đều là mã của app mobile: B quét QR của A (mang h/p + mã ghép đôi) rồi gọi thẳng
// vào máy chủ của A. Không có node desktop nào tham gia phiên này — đúng mô hình ngang hàng.
console.log("\n--- hai điện thoại nhắn thẳng với nhau (B quét QR của A) ---");
{
  await cho(300);
  const kpB = genKeypair();
  const dtB = { priv: kpB.priv, pub: kpB.pub, name: "Điện thoại B" };
  maQr = newPairCode();                       // A đang hiện mã mới trên QR
  suDT.approval.length = 0;
  const truoc = suDT.connected.length;
  const nhanB = [], vaoB = [];
  const B = new PeerLink({
    identity: dtB, expectPub: dienThoai.pub, pairCode: maQr,   // lấy từ QR của A
    lookupContact: async () => null,
    onConnected: (i) => vaoB.push(i), onMessage: (m) => nhanB.push(m), onNotice: () => {}, onDisconnected: () => {},
  });
  B.connect("127.0.0.1", congDT);
  dat("A hỏi duyệt B (khóa B chưa có trong danh bạ A)", await doiDen(() => suDT.approval.length === 1));
  phien.approve();
  dat("hai điện thoại vào phòng", await doiDen(() => vaoB.length === 1 && suDT.connected.length > truoc));
  const vaoA = suDT.connected.at(-1) || {};
  dat("B: khóa A khớp khóa lấy từ QR ⇒ tin cậy", vaoB[0]?.trusted === true);
  dat("A: B chứng minh đã quét mã của A ⇒ ghép đôi hai chiều", vaoA.peerProvedPair === true);
  dat("safety number hai điện thoại khớp", B.session.safety === phien.session.safety);
  B.sendText("B gửi A — không qua máy tính nào");
  dat("A giải mã tin của B", await doiDen(() => suDT.msg.some((m) => m.text === "B gửi A — không qua máy tính nào")));
  phien.sendText("A trả lời B");
  dat("B giải mã tin của A", await doiDen(() => nhanB.some((m) => m.text === "A trả lời B")));
  const tep = crypto.randomBytes(400 * 1024);
  B.sendFile({ base64: tep.toString("base64"), name: "anh-tu-B.jpg", mime: "image/jpeg" });
  dat("A nhận tệp 400 KB của B, SHA-256 khớp", await doiDen(() => suDT.msg.some((m) => m.type === "file" && m.name === "anh-tu-B.jpg" && m.integrity === true), 8000));
  B.close();
}

mayChuDT.close();
await D.stop();
fs.rmSync(thuMuc, { recursive: true, force: true });
console.log(loi ? `\n${loi} MỤC SAI` : "\nTẤT CẢ ĐẠT");
process.exit(loi ? 1 : 0);
