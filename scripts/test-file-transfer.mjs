// Thử gửi tệp THẬT giữa hai node chạy song song trên máy này: đo số byte đi trên dây,
// kiểm tệp nhận về khớp từng byte, và kiểm đường lùi JSON+base64 vẫn hoạt động.
//
//   node scripts/test-file-transfer.mjs
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "../desktop/server/index.js";

const goc = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(goc, "../web");
let loi = 0;
const dat = (ten, ok, them = "") => {
  console.log(`${ten.padEnd(46, " ")} ${ok ? "OK" : "SAI"}${them ? "   " + them : ""}`);
  if (!ok) loi++;
};
const cho = (ms) => new Promise((r) => setTimeout(r, ms));

/** Gắn một "giao diện" giả để đọc được các sự kiện node phát ra. */
function ngheUi(node) {
  const su = [];
  node.uiClients.add({ send: (s) => su.push(JSON.parse(s)) });
  return su;
}
async function doiSuKien(su, hop, hanGio = 15000) {
  const het = Date.now() + hanGio;
  while (Date.now() < het) {
    const m = su.find(hop);
    if (m) return m;
    await cho(30);
  }
  throw new Error("Quá hạn chờ sự kiện");
}

async function chay({ epJsonB64 }) {
  const thuMuc = fs.mkdtempSync(path.join(os.tmpdir(), "sentinell-test-"));
  const A = await startServer({ dataDir: path.join(thuMuc, "a"), port: 8190, webDir });
  const B = await startServer({ dataDir: path.join(thuMuc, "b"), port: 8191, webDir });
  const suA = ngheUi(A.node), suB = ngheUi(B.node);

  A.node.connectPeer("127.0.0.1", B.port, null, null);
  await doiSuKien(suB, (m) => m.type === "approval_request");
  B.node.approveIncoming();
  await doiSuKien(suA, (m) => m.type === "connected");
  await doiSuKien(suB, (m) => m.type === "connected");

  if (epJsonB64) {
    // Giả lập đối phương cũ (node Python): xóa khai báo năng lực ⇒ phải tự lùi về base64.
    A.node.session.peer.feat = [];
    B.node.session.peer.feat = [];
  }
  dat(`kênh dùng: ${A.node.session.peerBinary ? "nhị phân" : "JSON+base64"}`,
    A.node.session.peerBinary === !epJsonB64);

  // Đếm byte thực sự rời socket của A.
  let byteDay = 0;
  const wsA = A.node.peerWs;
  const guiGoc = wsA.send.bind(wsA);
  wsA.send = (d, ...r) => { byteDay += typeof d === "string" ? Buffer.byteLength(d) : d.length; return guiGoc(d, ...r); };

  const tep = crypto.randomBytes(8 * 1024 * 1024);          // 8 MB
  const bam = crypto.createHash("sha256").update(tep).digest("hex");
  const batDau = Date.now();
  await A.node.sendFile("báo cáo đồ án.pdf", "application/pdf", tep);
  const nhan = await doiSuKien(suB, (m) => m.type === "message" && m.body?.type === "file", 60000);
  const giay = (Date.now() - batDau) / 1000;

  dat("tên tệp (có dấu) tới nơi nguyên vẹn", nhan.body.name === "báo cáo đồ án.pdf");
  dat("kích thước khớp", nhan.body.size === tep.length);
  dat("B báo toàn vẹn ✓", nhan.body.integrity === true);

  const duoc = fs.readFileSync(path.join(B.node.storage.filesDir,
    path.basename(nhan.body.url.replace("/file/", ""))));
  dat("nội dung khớp từng byte", crypto.createHash("sha256").update(duoc).digest("hex") === bam);

  const ty = byteDay / tep.length;
  dat(`byte trên dây / byte tệp = ${ty.toFixed(2)}`, epJsonB64 ? ty > 2 : ty < 1.02);
  console.log(`   ${(tep.length / 1048576).toFixed(0)} MB trong ${giay.toFixed(2)}s `
    + `(${(tep.length / 1048576 / giay).toFixed(0)} MB/s), gửi ${(byteDay / 1048576).toFixed(1)} MB`);

  // Tiến độ có được báo ra giao diện không?
  const td = suA.filter((m) => m.type === "file_progress" && m.dir === "out");
  dat("có báo tiến độ cho bên gửi", td.length > 1 && td[td.length - 1].done === td[td.length - 1].total);
  dat("có báo tiến độ cho bên nhận", suB.some((m) => m.type === "file_progress" && m.dir === "in"));

  // Nhắn chữ sau khi truyền tệp: ratchet hai bên còn khớp nhau không?
  A.node.sendText("xong tệp rồi nhé");
  const chu = await doiSuKien(suB, (m) => m.type === "message" && m.body?.type === "text");
  dat("nhắn chữ tiếp sau tệp vẫn giải mã được", chu.body.text === "xong tệp rồi nhé");

  await A.stop(); await B.stop();
  fs.rmSync(thuMuc, { recursive: true, force: true });
}

console.log("--- đường nhị phân (mặc định) ---");
await chay({ epJsonB64: false });
console.log("\n--- đường lùi JSON+base64 (peer kiểu cũ, vd node Python) ---");
await chay({ epJsonB64: true });

console.log(loi === 0 ? "\nTẤT CẢ ĐẠT" : `\n${loi} MỤC SAI`);
process.exit(loi === 0 ? 0 : 1);
