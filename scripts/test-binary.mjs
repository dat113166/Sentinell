// Kiểm chứng khung nhị phân của core: bắt tay -> gửi xen kẽ chữ + khối nhị phân
// hai chiều, kiểm ratchet đồng bộ, kiểm GCM từ chối khi sửa 1 byte.
import crypto from "node:crypto";
import { Session, genKeypair, isBinaryFrame } from "@sentinell/core";

let loi = 0;
const dat = (ten, ok) => {
  console.log(`${ten.padEnd(52, " ")} ${ok ? "OK" : "SAI"}`);
  if (!ok) loi++;
};

const a = genKeypair(), b = genKeypair();
const A = new Session({ role: "I", idPriv: a.priv, idPub: a.pub, name: "A" });
const B = new Session({ role: "R", idPriv: b.priv, idPub: b.pub, name: "B" });

// Đúng luồng thật: MỖI bên gửi hs, mỗi bên đáp hs-sig, rồi mỗi bên onSig.
const hiA = A.hello(), hiB = B.hello();
const sigB = B.onHello(hiA);
const sigA = A.onHello(hiB);
A.onSig(sigB, null);
B.onSig(sigA, null);

dat("bắt tay: hai bên sẵn sàng", A.ready && B.ready);
dat("safety number khớp", A.safety === B.safety && A.safety.length > 0);
dat("A thấy B hiểu khung nhị phân", A.peerBinary === true);
dat("B thấy A hiểu khung nhị phân", B.peerBinary === true);

// --- xen kẽ chữ và nhị phân theo đúng thứ tự WebSocket ---
const goc = crypto.randomBytes(300 * 1024);
dat("B giải mã được tin chữ", B.decrypt(A.encrypt("text", { text: "chào" })).text === "chào");

const khung = A.encryptBinary("file-chunk", { name: "ảnh mèo.png", idx: 0 }, goc, true);
dat("khung có magic SNT1", isBinaryFrame(khung));
const r = B.decryptBinary(khung, true);
dat("mtype đúng", r.mtype === "file-chunk");
dat("tên tệp (có dấu) đi qua vùng mã hóa", r.meta.name === "ảnh mèo.png");
dat("bytes khớp từng byte", Buffer.compare(Buffer.from(r.bytes), goc) === 0);
dat("tên tệp KHÔNG lộ ra phần đầu khung",
  !Buffer.from(khung).toString("latin1").includes("png"));

const ty = khung.length / goc.length;
dat(`không phình (tỉ lệ ${ty.toFixed(4)} ≤ 1,01)`, ty <= 1.01);

// --- chiều ngược lại ---
const goc2 = crypto.randomBytes(64 * 1024);
const r2 = A.decryptBinary(B.encryptBinary("file-chunk", { name: "b.bin", idx: 3 }, goc2, true), true);
dat("chiều B→A cũng đúng", Buffer.compare(Buffer.from(r2.bytes), goc2) === 0 && r2.meta.idx === 3);

// --- ratchet: mỗi khối tiêu đúng 1 bước, chữ và nhị phân chung bộ đếm ---
const truoc = A.sendSeq;
for (let i = 0; i < 5; i++) {
  B.decryptBinary(A.encryptBinary("file-chunk", { idx: i }, Buffer.alloc(16), true), true);
}
dat("seq tiến đúng 5 bước", A.sendSeq - truoc === 5 && B.recvSeq === A.sendSeq);
dat("nhắn chữ tiếp sau tệp vẫn giải mã được",
  B.decrypt(A.encrypt("text", { text: "sau tệp" })).text === "sau tệp");

// --- toàn vẹn: sửa 1 byte trong bản mã -> GCM phải từ chối ---
const hong = Uint8Array.from(A.encryptBinary("file-chunk", { idx: 9 }, goc2, true));
hong[hong.length - 40] ^= 1;
let bat = false;
try { B.decryptBinary(hong, true); } catch { bat = true; }
dat("sửa 1 byte → GCM từ chối", bat);

// --- không thể tráo khung nhị phân thành gói JSON cùng seq/type (AAD khác nhau) ---
const A2 = new Session({ role: "I", idPriv: a.priv, idPub: a.pub, name: "A" });
const B2 = new Session({ role: "R", idPriv: b.priv, idPub: b.pub, name: "B" });
const s1 = B2.onHello(A2.hello()), s2 = A2.onHello(B2.hello());
A2.onSig(s1, null); B2.onSig(s2, null);
const kh = A2.encryptBinary("file-chunk", { idx: 0 }, Buffer.alloc(32), true);
// lấy bản mã của khung nhị phân, nhét vào khuôn JSON cùng seq/dir/mtype
const ctHex = Buffer.from(kh.subarray(10 + "file-chunk".length)).toString("hex");
let choi = false;
try { B2.decrypt({ type: "msg", seq: 0, dir: 0, mtype: "file-chunk", ct: ctHex }); } catch { choi = true; }
dat("tráo khung nhị phân sang khuôn JSON → bị từ chối", choi);

console.log(loi === 0 ? "\nTẤT CẢ ĐẠT" : `\n${loi} MỤC SAI`);
process.exit(loi === 0 ? 0 : 1);
