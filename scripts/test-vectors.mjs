// Bước 2/3 test interop: JavaScript (core/protocol.js) kiểm chứng vector của Python,
// rồi tự sinh chữ ký + bản mã để Python kiểm chứng ngược (bước 3).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Session, sha256, hexToBytes, bytesToHex, verify, fingerprint, safetyNumber } from "@sentinell/core";

const here = path.dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(fs.readFileSync(path.join(here, "vectors.json"), "utf8"));

let fails = 0;
const check = (name, ok, extra = "") => {
  console.log(`${ok ? "  ✓" : "  ✗"} ${name}${extra ? " — " + extra : ""}`);
  if (!ok) fails++;
};

// Dựng lại đúng hai phiên với khóa/nonce cố định
const A = new Session({ role: "I", idPriv: V.id_a.priv, idPub: V.id_a.pub, name: "Alice" });
const B = new Session({ role: "R", idPriv: V.id_b.priv, idPub: V.id_b.pub, name: "Bob" });
A.ephPriv = V.eph_a.priv; A.ephPub = V.eph_a.pub; A.nonce = V.nonce_a;
B.ephPriv = V.eph_b.priv; B.ephPub = V.eph_b.pub; B.nonce = V.nonce_b;

const hi = A.hello(), hr = B.hello();
const sigB = B.onHello(hi);
const sigA = A.onHello(hr);

console.log("[js] kiểm chứng vector Python:");
check("fingerprint A/B khớp", fingerprint(V.id_a.pub) === V.fp_a && fingerprint(V.id_b.pub) === V.fp_b);
check("safety number khớp", safetyNumber(V.id_a.pub, V.id_b.pub) === V.safety);
const tHash = bytesToHex(sha256(A._transcript()));
check("transcript SHA-256 khớp", tHash === V.transcript_sha256, tHash.slice(0, 16) + "…");
check("JS xác minh chữ ký DER của Python (A)", verify(V.id_a.pub, V.sig_a_der, hexToBytes(V.transcript_sha256)));
check("JS xác minh chữ ký DER của Python (B)", verify(V.id_b.pub, V.sig_b_der, hexToBytes(V.transcript_sha256)));

// Hoàn tất bắt tay trong JS bằng chữ ký CỦA PYTHON (mô phỏng peer Python)
A.onSig({ sig: V.sig_b_der }, V.id_b.pub);
B.onSig({ sig: V.sig_a_der }, V.id_a.pub);
check("A/B sẵn sàng & tin cậy", A.ready && B.ready && A.trusted && B.trusted);
check("recv chain key của A khớp Python", bytesToHex(A.recvCK) === V.a_recv_ck);

// Giải mã bản mã seq0 do Python A sinh, bằng JS B
let dec = null;
try { dec = B.decrypt(V.msg0_from_a); } catch (e) { dec = null; }
check("JS B giải mã được bản mã của Python A", !!dec && dec.type === "text" && dec.text === "vector", JSON.stringify(dec));

// JS A mã hóa seq0 (cùng chain) → send_ck sau ratchet phải khớp Python
const msgJs = A.encrypt("text", { text: "vector-js" });
check("send chain key của A sau ratchet khớp Python", bytesToHex(A.sendCK) === V.a_send_ck_after_msg0);

fs.writeFileSync(path.join(here, "js-out.json"), JSON.stringify({
  sig_a_der_js: sigA.sig, sig_b_der_js: sigB.sig, msg0_from_a_js: msgJs,
}, null, 2));
console.log(`[js] ${fails === 0 ? "TẤT CẢ ĐẠT" : fails + " lỗi"} — đã ghi scripts/js-out.json`);
process.exit(fails ? 1 : 0);
