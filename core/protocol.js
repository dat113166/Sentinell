// Sentinell — lõi giao thức mật mã, viết MỘT LẦN bằng JavaScript, chạy được ở cả:
//   • Node.js (tiến trình chính của Electron — node trên PC)
//   • Trình duyệt (trang /join cho điện thoại; được esbuild đóng gói vào web/vendor/)
//   • React Native (tuần 2)
//
// Khuôn gói tin, cách dựng transcript, HKDF, nonce, AAD và định dạng chữ ký (DER) được
// giữ ĐÚNG như bản tham chiếu Python (reference/python/sentinell/crypto.py), nên node
// Python cũ vẫn bắt tay và nhắn tin được với Electron — dùng làm bài test interop.
//
// Ánh xạ lý thuyết (docs/BAOCAO.md): danh tính ECDSA P-256 (chữ ký số, ch.3 bài giảng);
// bắt tay ECDH tạm thời có ký transcript (mục 4.2/4.4/4.5); HKDF-SHA256 (4.1.3);
// AES-256-GCM (giáo trình 2.6.5); ratchet mỗi tin (4.10); safety number (4.5).
// Toàn bộ dùng thư viện đã kiểm định @noble/* (khuyến cáo mục 4.8).

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { gcm } from "@noble/ciphers/aes.js";
import {
  bytesToHex, hexToBytes, randomBytes, concatBytes, utf8ToBytes,
} from "@noble/hashes/utils.js";

const te = new TextEncoder();
const td = new TextDecoder();
const EMPTY = new Uint8Array(0);

export const ROOT_INFO = utf8ToBytes("sentinell-root-v2");
export const TRANSCRIPT_TAG = utf8ToBytes("sentinell-hs-v2");
const MSG_INFO = utf8ToBytes("sentinell-msg");
const CHAIN_INFO = utf8ToBytes("sentinell-chain");

/** Năng lực bản này khai trong handshake. "bin" = hiểu khung nhị phân (gửi tệp). */
export const FEATURES = ["bin"];

// ------------------------------------------- giới hạn cho dữ liệu do ĐỐI PHƯƠNG gửi
// Phần mô tả tệp (`file-meta`) đến từ máy bên kia, nên MỌI con số trong đó đều là do họ
// nói. Trước 3.15.0 ta cấp phát thẳng `new Array(obj.chunks)` — đối phương chỉ cần gửi
// `chunks: 50000000` là bên nhận cấp phát vài GB rồi chết. Bắt tay thành công KHÔNG có
// nghĩa là bên kia thiện chí: khóa của họ có thể đã bị đánh cắp, hoặc chính họ đổi ý.
export const KHOI_TEP = 256 * 1024;
export const TEP_TOI_DA = 200 * 1024 * 1024;
export const SO_KHOI_TOI_DA = Math.ceil(TEP_TOI_DA / KHOI_TEP) + 8;
export const SO_TEP_NHAN_CUNG_LUC = 4;
const TEN_TEP_TOI_DA = 260;              // đủ dài cho mọi tên thật, chặn tên rác

/** Kiểm phần mô tả tệp trước khi cấp phát bất cứ thứ gì. Trả về câu lỗi, hoặc null nếu ổn. */
export function loiMoTaTep(meta) {
  if (!meta || typeof meta !== "object") return "gói mô tả tệp không hợp lệ";
  const { name, chunks, size } = meta;
  if (typeof name !== "string" || !name || name.length > TEN_TEP_TOI_DA) return "tên tệp không hợp lệ";
  if (!Number.isInteger(chunks) || chunks < 1 || chunks > SO_KHOI_TOI_DA) {
    return `số khối không hợp lệ (${chunks}) — tệp tối đa ${TEP_TOI_DA / 1048576} MB`;
  }
  if (size !== undefined && (!Number.isFinite(size) || size < 0 || size > TEP_TOI_DA)) {
    return "kích thước tệp vượt mức cho phép";
  }
  return null;
}

// ------------------------------------------------ khung nhị phân cho tệp lớn
// Đường tin nhắn thường gói mọi thứ vào JSON, nên một tệp phải qua base64 (+33%)
// rồi bản mã lại in ra chuỗi hex (+100%): 1 byte tệp hóa 2,67 byte trên dây. Tệ hơn
// cả số đó là việc dựng chuỗi — 10 MB tệp thành một chuỗi 27 MB phải JSON.parse một
// lần, đủ để đứng hình giao diện. Khung này gửi thẳng bytes, không qua chuỗi nào.
//
//   "SNT1" | dir(1) | độ dài mtype(1) | seq(4, BE) | mtype utf8 | bản mã GCM
//   bản mã = GCM( u16BE(độ dài meta) ‖ meta JSON utf8 ‖ bytes thô )
//
// Phần đầu chỉ để lộ đúng những trường mà gói JSON vốn cũng để lộ (seq, dir, mtype)
// — phải biết chúng mới dựng được AAD để giải mã. TÊN TỆP nằm trong meta, tức nằm
// trong vùng đã mã hóa, y như ở đường JSON.
const BIN_MAGIC = [0x53, 0x4e, 0x54, 0x31];   // "SNT1"
const BIN_HEAD = 10;                          // magic 4 + dir 1 + mtypeLen 1 + seq 4

/** Khung đến là khung nhị phân của Sentinell hay là JSON dạng chữ? */
export function isBinaryFrame(u8) {
  return !!u8 && u8.length >= BIN_HEAD
    && u8[0] === BIN_MAGIC[0] && u8[1] === BIN_MAGIC[1]
    && u8[2] === BIN_MAGIC[2] && u8[3] === BIN_MAGIC[3];
}

/** Bytes vào, bất kể là Buffer (Node), Uint8Array hay ArrayBuffer (trình duyệt). */
export function toBytes(x) {
  if (x instanceof Uint8Array) return x;                    // Buffer của Node cũng vào nhánh này
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  return new Uint8Array(x);
}

// ------------------------------------------------------------ tiện ích khóa/băm
export function genKeypair() {
  const kp = p256.keygen();
  return { priv: bytesToHex(kp.secretKey), pub: bytesToHex(kp.publicKey) }; // pub nén 33B
}

export function sha256Hex(bytes) {
  return bytesToHex(sha256(bytes));
}

export function fingerprint(pubHex) {
  return bytesToHex(sha256(hexToBytes(pubHex))).slice(0, 16);
}

/** 60 chữ số (12 nhóm 5) từ SHA-256 của hai khóa danh tính, thứ tự cố định. */
export function safetyNumber(pubA, pubB) {
  const [lo, hi] = [pubA, pubB].sort();
  const h1 = sha256(concatBytes(hexToBytes(lo), hexToBytes(hi)));
  const h2 = sha256(h1);
  const buf = concatBytes(h1, h2);
  const groups = [];
  for (let i = 0; i < 12; i++) {
    const v = ((buf[i * 4] << 24) | (buf[i * 4 + 1] << 16) | (buf[i * 4 + 2] << 8) | buf[i * 4 + 3]) >>> 0;
    groups.push(String(v % 100000).padStart(5, "0"));
  }
  return groups.join(" ");
}

/** Ký `data` bằng ECDSA(SHA-256): noble tự băm data rồi ký (prehash:true), xuất DER
 *  — giống hệt `priv.sign(data, ECDSA(SHA256()))` của cryptography (Python). */
export function sign(privHex, data) {
  return bytesToHex(p256.sign(data, hexToBytes(privHex), { prehash: true, format: "der" }));
}

export function verify(pubHex, sigHex, data) {
  try {
    // lowS:false — chấp nhận cả chữ ký "high-S" do thư viện cryptography (Python) sinh ra;
    // bản thân JS luôn ký low-S nên không ảnh hưởng tính chống malleability của ta.
    return p256.verify(hexToBytes(sigHex), data, hexToBytes(pubHex), { prehash: true, format: "der", lowS: false });
  } catch {
    return false;
  }
}

/** Bí mật chung ECDH = tọa độ x (32 byte) — bỏ prefix 0x02/0x03 của điểm nén. */
export function ecdhX(privHex, peerPubHex) {
  return p256.getSharedSecret(hexToBytes(privHex), hexToBytes(peerPubHex)).slice(1);
}

function hkdf32(ikm, salt, info) {
  return hkdf(sha256, ikm, salt, info, 32);
}

export function seqNonce(dir, seq) {
  const n = new Uint8Array(12);
  n[0] = dir & 0xff;
  n[8] = (seq >>> 24) & 0xff;
  n[9] = (seq >>> 16) & 0xff;
  n[10] = (seq >>> 8) & 0xff;
  n[11] = seq & 0xff;
  return n;
}

// ------------------------------------------------------------ phiên bảo mật
/**
 * Một phiên giữa node này và một peer. role: "I" (bên chủ động kết nối) | "R".
 * Các gói trả về/nhận vào là object JSON, gửi nguyên văn qua WebSocket /peer.
 */
export class Session {
  constructor({ role, idPriv, idPub, name = "?", onLog = null, pairCode = null, activePairCode = null, listenPort = null }) {
    this.role = role;
    this.idPriv = idPriv;
    this.idPub = idPub;
    this.name = name;
    this.onLog = onLog;
    this.pairCode = pairCode;                 // mã tôi ĐÃ QUÉT của đối phương → tôi chứng minh
    this.activePairCode = activePairCode;     // mã TÔI ĐANG HIỆN → tôi kiểm chứng minh của họ
    this.peerProvedPair = false;              // đối phương đã chứng minh quét mã của tôi?
    this.listenPort = listenPort;             // cổng tôi đang lắng nghe (để họ gọi lại được)

    const eph = genKeypair();
    this.ephPriv = eph.priv;
    this.ephPub = eph.pub;
    this.nonce = bytesToHex(randomBytes(16));

    this.peer = null;
    this.ready = false;
    this.authFailed = false;
    this.trusted = false;
    this.sendCK = null;
    this.recvCK = null;
    this.sendSeq = 0;
    this.recvSeq = 0;
    this.safety = "";
  }

  get dir() { return this.role === "I" ? 0 : 1; }

  _log(step, detail) { if (this.onLog) this.onLog(step, detail); }

  /** Đối phương có hiểu khung nhị phân không. Node Python tham chiếu thì không —
   *  với nó ta tự động lùi về đường JSON+base64 cũ (chậm nhưng vẫn chạy). */
  get peerBinary() {
    return Array.isArray(this.peer?.feat) && this.peer.feat.includes("bin");
  }

  // ---- gói handshake đầu tiên ----
  hello() {
    this._log("hs-send", `Gửi handshake: id=${this.idPub.slice(0, 16)}… eph=${this.ephPub.slice(0, 16)}… nonce=${this.nonce.slice(0, 12)}…`);
    return {
      type: "hs", id_pub: this.idPub, eph_pub: this.ephPub, nonce: this.nonce,
      name: this.name, listen_port: this.listenPort,
      // Khai năng lực. KHÔNG nằm trong transcript được ký: kẻ đứng giữa gỡ trường này
      // chỉ ép được hai bên gửi tệp theo đường chậm hơn, không đọc thêm được gì.
      feat: FEATURES,
    };
  }

  _transcript() {
    const me = { id: this.idPub, eph: this.ephPub, nonce: this.nonce };
    const them = { id: this.peer.id_pub, eph: this.peer.eph_pub, nonce: this.peer.nonce };
    const [I, R] = this.role === "I" ? [me, them] : [them, me];
    return concatBytes(
      TRANSCRIPT_TAG,
      hexToBytes(I.id), hexToBytes(I.eph), hexToBytes(I.nonce),
      hexToBytes(R.id), hexToBytes(R.eph), hexToBytes(R.nonce),
    );
  }

  // ---- nhận handshake của peer → trả về gói chữ ký ----
  onHello(data) {
    this.peer = {
      id_pub: data.id_pub, eph_pub: data.eph_pub, nonce: data.nonce, name: data.name || "?",
      feat: Array.isArray(data.feat) ? data.feat : [],
    };
    this._log("hs-recv", `Nhận handshake của ${this.peer.name}: id=${data.id_pub.slice(0, 16)}…`);
    const h = sha256(this._transcript());
    const sig = sign(this.idPriv, h);
    this._log("sign", `Ký transcript (SHA-256) bằng ECDSA: ${sig.slice(0, 24)}…`);
    const out = { type: "hs-sig", sig, feat: FEATURES };
    if (this.pairCode) {
      out.pair_proof = pairProof(this.pairCode, h);
      this._log("pair", "Gửi bằng chứng đã quét mã ghép đôi (HMAC gắn với transcript).");
    }
    return out;
  }

  // ---- nhận chữ ký của peer → xác minh + dẫn xuất khóa ----
  onSig(data, pinnedPub = null) {
    if (Array.isArray(data.feat)) this.peer.feat = data.feat;   // bên R khai năng lực ở gói này
    const h = sha256(this._transcript());
    if (!verify(this.peer.id_pub, data.sig, h)) {
      this.authFailed = true;
      this._log("verify-fail", "❌ Chữ ký peer KHÔNG hợp lệ — nghi ngờ kẻ đứng giữa! Hủy bắt tay.");
      return;
    }
    if (pinnedPub !== null && pinnedPub !== undefined) {
      if (pinnedPub === this.peer.id_pub) {
        this.trusted = true;
        this._log("verify-ok", "✅ Chữ ký hợp lệ và khóa KHỚP khóa đã ghim qua QR — tin cậy.");
      } else {
        this.authFailed = true;
        this._log("verify-fail", "❌ Chữ ký hợp lệ nhưng khóa KHÁC khóa đã ghim qua QR — có thể bị mạo danh!");
        return;
      }
    } else {
      this._log("verify-ok", "✅ Chữ ký hợp lệ (chưa ghim khóa — nên quét QR để xác minh out-of-band).");
    }

    // Nếu TÔI đang hiện mã ghép đôi và đối phương chứng minh đã thấy mã đó,
    // thì khóa của họ cũng được xác thực ngoài kênh ⇒ tự ghim ⇒ GHIM HAI CHIỀU.
    if (this.activePairCode && data.pair_proof) {
      if (verifyPairProof(this.activePairCode, h, data.pair_proof)) {
        this.trusted = true;
        this.peerProvedPair = true;
        this._log("pair", "✅ Đối phương chứng minh đã quét mã ghép đôi của tôi — tự ghim khóa họ (khỏi phải quét ngược).");
      } else {
        this._log("warn", "⚠️ Bằng chứng ghép đôi không khớp — không tự ghim khóa đối phương.");
      }
    }

    const x = ecdhX(this.ephPriv, this.peer.eph_pub);
    const nonceI = this.role === "I" ? this.nonce : this.peer.nonce;
    const nonceR = this.role === "I" ? this.peer.nonce : this.nonce;
    const salt = concatBytes(hexToBytes(nonceI), hexToBytes(nonceR));
    const okm = hkdf(sha256, x, salt, ROOT_INFO, 64);
    const ckI2R = okm.slice(0, 32), ckR2I = okm.slice(32, 64);
    if (this.role === "I") { this.sendCK = ckI2R; this.recvCK = ckR2I; }
    else { this.sendCK = ckR2I; this.recvCK = ckI2R; }
    this.ready = true;
    this.safety = safetyNumber(this.idPub, this.peer.id_pub);
    this._log("derive", "ECDH→x, HKDF→root(64B), tách 2 chain key theo chiều. Sẵn sàng.");
    this._log("safety", `Safety number: ${this.safety}`);
  }

  // ---- mã hóa một thông điệp ----
  encrypt(mtype, obj) {
    if (!this.ready) throw new Error("Phiên chưa sẵn sàng");
    const seq = this.sendSeq++;
    const mk = hkdf32(this.sendCK, EMPTY, MSG_INFO);
    this.sendCK = hkdf32(this.sendCK, EMPTY, CHAIN_INFO);
    const aad = te.encode(JSON.stringify({ seq, dir: this.dir, type: mtype }));
    const nonce = seqNonce(this.dir, seq);
    const plaintext = te.encode(JSON.stringify({ type: mtype, ...obj }));
    const ct = bytesToHex(gcm(mk, nonce, aad).encrypt(plaintext));
    mk.fill(0);
    this._log("encrypt", `AES-256-GCM (khóa ratchet seq=${seq}) → ${ct.slice(0, 24)}…  | chain key tiến 1 bước`);
    return { type: "msg", seq, dir: this.dir, mtype, ct };
  }

  // ---- giải mã một thông điệp ----
  decrypt(payload) {
    const seq = payload.seq;
    if (seq !== this.recvSeq) {
      this._log("warn", `⚠️ seq nhận (${seq}) lệch dự kiến (${this.recvSeq}) — có thể có gói bị chèn thêm, gửi lặp lại, hoặc rớt mất.`);
    }
    const mk = hkdf32(this.recvCK, EMPTY, MSG_INFO);
    this.recvCK = hkdf32(this.recvCK, EMPTY, CHAIN_INFO);
    this.recvSeq = seq + 1;
    const aad = te.encode(JSON.stringify({ seq, dir: payload.dir, type: payload.mtype }));
    const nonce = seqNonce(payload.dir, seq);
    let pt;
    try {
      pt = gcm(mk, nonce, aad).decrypt(hexToBytes(payload.ct));
    } catch (e) {
      mk.fill(0);
      this._log("decrypt-fail", `❌ GCM từ chối giải mã seq=${seq} — bản mã đã bị sửa hoặc sai khóa (kiểm tra toàn vẹn thất bại).`);
      throw e;
    }
    mk.fill(0);
    this._log("decrypt", `Giải mã + kiểm toàn vẹn GCM seq=${seq} OK`);
    return JSON.parse(td.decode(pt));
  }

  // ---- mã hóa một khối nhị phân (tệp) ----
  // Dùng CHUNG bộ đếm seq và CHUNG chain key với tin nhắn chữ: một khối tệp tiêu tốn
  // một bước ratchet đúng như một tin nhắn, nên thứ tự và tính "một khóa một lần"
  // không đổi. WebSocket giữ nguyên thứ tự giữa khung chữ và khung nhị phân nên hai
  // luồng vẫn khớp nhau.
  encryptBinary(mtype, meta, bytes, quiet = false) {
    if (!this.ready) throw new Error("Phiên chưa sẵn sàng");
    const body = toBytes(bytes);
    const seq = this.sendSeq++;
    const mk = hkdf32(this.sendCK, EMPTY, MSG_INFO);
    this.sendCK = hkdf32(this.sendCK, EMPTY, CHAIN_INFO);
    // Thêm bin:1 vào AAD để khung nhị phân và gói JSON không thể tráo cho nhau
    // dù cùng seq/dir/type — GCM sẽ từ chối ngay.
    const aad = te.encode(JSON.stringify({ seq, dir: this.dir, type: mtype, bin: 1 }));
    const metaBytes = te.encode(JSON.stringify(meta));
    if (metaBytes.length > 0xffff) throw new Error("Phần mô tả tệp quá dài");

    const pt = new Uint8Array(2 + metaBytes.length + body.length);
    pt[0] = metaBytes.length >>> 8;
    pt[1] = metaBytes.length & 0xff;
    pt.set(metaBytes, 2);
    pt.set(body, 2 + metaBytes.length);

    const ct = gcm(mk, seqNonce(this.dir, seq), aad).encrypt(pt);
    mk.fill(0);
    pt.fill(0);

    const mt = te.encode(mtype);
    const out = new Uint8Array(BIN_HEAD + mt.length + ct.length);
    out.set(BIN_MAGIC, 0);
    out[4] = this.dir & 0xff;
    out[5] = mt.length & 0xff;
    out[6] = (seq >>> 24) & 0xff; out[7] = (seq >>> 16) & 0xff;
    out[8] = (seq >>> 8) & 0xff;  out[9] = seq & 0xff;
    out.set(mt, BIN_HEAD);
    out.set(ct, BIN_HEAD + mt.length);

    if (!quiet) {
      this._log("encrypt", `AES-256-GCM khung nhị phân (khóa ratchet seq=${seq}) — `
        + `${(body.length / 1024).toFixed(0)} KB dữ liệu thô, gửi thẳng bytes (không base64/hex).`);
    }
    return out;
  }

  // ---- giải mã một khối nhị phân ----
  decryptBinary(frame, quiet = false) {
    const u8 = toBytes(frame);
    if (!isBinaryFrame(u8)) throw new Error("Khung nhị phân sai định dạng");
    const dir = u8[4];
    const mtLen = u8[5];
    const seq = ((u8[6] << 24) | (u8[7] << 16) | (u8[8] << 8) | u8[9]) >>> 0;
    if (u8.length < BIN_HEAD + mtLen) throw new Error("Khung nhị phân bị cụt");
    const mtype = td.decode(u8.subarray(BIN_HEAD, BIN_HEAD + mtLen));
    const ct = u8.subarray(BIN_HEAD + mtLen);

    if (seq !== this.recvSeq) {
      this._log("warn", `⚠️ seq nhận (${seq}) lệch dự kiến (${this.recvSeq}) — có thể có gói bị chèn thêm, gửi lặp lại, hoặc rớt mất.`);
    }
    const mk = hkdf32(this.recvCK, EMPTY, MSG_INFO);
    this.recvCK = hkdf32(this.recvCK, EMPTY, CHAIN_INFO);
    this.recvSeq = seq + 1;

    const aad = te.encode(JSON.stringify({ seq, dir, type: mtype, bin: 1 }));
    let pt;
    try {
      pt = gcm(mk, seqNonce(dir, seq), aad).decrypt(ct);
    } catch (e) {
      mk.fill(0);
      this._log("decrypt-fail", `❌ GCM từ chối giải mã khung nhị phân seq=${seq} — dữ liệu đã bị sửa hoặc sai khóa (kiểm tra toàn vẹn thất bại).`);
      throw e;
    }
    mk.fill(0);

    const metaLen = (pt[0] << 8) | pt[1];
    if (pt.length < 2 + metaLen) throw new Error("Phần mô tả tệp bị cụt");
    const meta = JSON.parse(td.decode(pt.subarray(2, 2 + metaLen)));
    const body = pt.subarray(2 + metaLen);
    if (!quiet) {
      this._log("decrypt", `Giải mã + kiểm toàn vẹn GCM khung nhị phân seq=${seq} OK — ${(body.length / 1024).toFixed(0)} KB.`);
    }
    return { mtype, seq, dir, meta, bytes: body };
  }
}


// ==========================================================================
// GHÉP ĐÔI (pairing) — giải bài toán "ghim QR một chiều".
//
// Vấn đề: bên QUÉT học được khóa của bên HIỆN QR, nhưng bên hiện QR không học
// được gì → chỉ một chiều nhắn được, lần sau phải quét ngược lại.
//
// Cách giải: QR (hoặc mã 3 từ) mang theo một MÃ GHÉP ĐÔI dùng một lần. Bên quét
// chứng minh "tôi đã thấy mã của bạn" bằng HMAC-SHA256(mã, transcript) gửi kèm
// chữ ký handshake. Bên hiện QR kiểm HMAC → tự ghim khóa bên kia ⇒ GHIM HAI CHIỀU
// chỉ với MỘT lần quét.
//
// Vì sao gửi HMAC chứ không gửi thẳng mã: mã đi ngoài kênh mạng (qua QR/đọc miệng),
// còn HMAC gắn chặt với transcript của đúng phiên này nên kẻ nghe lén không suy ra
// được mã, cũng không tái sử dụng được cho phiên khác (mục 4.5 + HMAC, giáo trình 4.1.3).
// ==========================================================================

/** Từ điển ghép đôi: từ tiếng Việt KHÔNG dấu, ngắn, dễ đọc qua điện thoại. */
export const PAIR_WORDS = [
  "mua", "gio", "nang", "may", "bien", "nui", "song", "rung", "cay", "hoa",
  "la", "qua", "hat", "re", "than", "canh", "chim", "ca", "voi", "gau",
  "meo", "cho", "ga", "vit", "ong", "buom", "kien", "tom", "cua", "rua",
  "den", "trang", "xanh", "do", "vang", "tim", "nau", "xam", "hong", "bac",
  "vang2", "dong", "sat", "chi", "kem", "nhom", "da", "go", "tre", "nua",
  "com", "pho", "bun", "mi", "chao", "banh", "keo", "duong", "muoi", "tieu",
  "ot", "toi", "hanh", "gung", "rieng", "sa", "que", "hoi", "tra", "ca2",
  "sua", "nuoc", "ruou", "bia", "dau", "muc", "thit", "trung", "rau", "nam",
  "mot", "hai", "ba", "bon", "nam2", "sau", "bay", "tam", "chin", "muoi2",
  "sang", "trua", "chieu", "toi2", "dem", "ngay", "tuan", "thang", "nam3", "mua2",
  "xuan", "ha", "thu", "dong2", "bac2", "trung2", "tay", "dong3", "trai", "phai",
  "tren", "duoi", "trong", "ngoai", "gan", "xa", "cao", "thap", "dai", "ngan",
  "rong", "hep", "day", "mong", "nang2", "nhe", "nhanh", "cham", "nong", "lanh",
  "am", "mat", "kho", "uot", "sach", "ban", "moi", "cu", "tot", "xau",
  "vui", "buon", "hien", "du", "manh", "yeu", "gioi", "dot", "sieng", "luoi",
  "nha", "cua2", "san", "vuon", "duong2", "cau", "pho2", "lang", "xa2", "huyen",
  "tinh", "thanh", "truong", "lop", "ban2", "ghe", "sach2", "vo", "but", "muc2",
  "giay", "keo2", "thuoc", "dan", "dao", "kim", "chi2", "vai", "ao", "quan",
  "mu", "non", "giay2", "dep", "tui", "vi", "dong ho", "kinh", "guong", "luoc",
  "xe", "tau", "thuyen", "bay2", "may bay", "xe dap", "o to", "tram", "ben", "cang",
  "nui2", "doi", "deo", "hang", "suoi", "ho", "dam", "vinh", "dao", "bo",
  "troi", "may2", "sao", "trang2", "mat troi", "gio2", "bao", "set", "suong", "tuyet",
  "lua", "khoi", "tro", "than2", "cui", "diem", "nen", "den2", "duoc", "pin",
  "loa", "dan2", "trong2", "sao2", "nhac", "hat2", "mua3", "kich", "phim", "anh",
  "chu", "so", "hinh", "mau", "net", "dong4", "cot", "bang", "o", "khung",
  "cua so", "cua chinh", "mai", "tuong", "nen2", "tran", "cot2", "keo3", "vua", "gach",
];

/** Sinh mã ghép đôi dạng 3 từ (ví dụ "mua-bien-xanh"). */
export function newPairCode(words = 3) {
  const r = randomBytes(words * 2);
  const out = [];
  for (let i = 0; i < words; i++) {
    const v = (r[i * 2] << 8) | r[i * 2 + 1];
    out.push(PAIR_WORDS[v % PAIR_WORDS.length]);
  }
  return out.join("-");
}

/** Chuẩn hóa mã người dùng gõ tay (bỏ hoa/thường, khoảng trắng, dấu cách thừa). */
export function normalizePairCode(code) {
  return String(code || "").trim().toLowerCase().replace(/[\s_]+/g, "-").replace(/-+/g, "-");
}

/** Bằng chứng đã thấy mã: HMAC-SHA256(mã, transcriptHash). */
export function pairProof(code, transcriptHash) {
  return bytesToHex(hmac(sha256, te.encode(normalizePairCode(code)), transcriptHash));
}

/** Kiểm bằng chứng, so sánh theo thời gian hằng định. */
export function verifyPairProof(code, transcriptHash, proofHex) {
  if (!code || !proofHex) return false;
  const want = pairProof(code, transcriptHash);
  if (want.length !== proofHex.length) return false;
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= want.charCodeAt(i) ^ proofHex.charCodeAt(i);
  return diff === 0;
}

// ==========================================================================
// ĐỌC NỘI DUNG QR — dùng chung cho web, desktop và mobile.
// App sinh ra vài dạng mã khác nhau, nên nơi nào đọc QR cũng phải hiểu ĐỦ cả:
//   1. Lời mời:  http://<ip>:<port>/join#k=<khóa>&n=<tên>&pc=<mã ghép đôi>
//   2. Khóa JSON: {"k":"<khóa>","n":"<tên>","fp":"…","pc":"…"}
//   3. Địa chỉ:   192.168.1.10:8000
//   4. Khóa trần: chuỗi hex 66 ký tự
// (Từng có lỗi: bản web chỉ đọc dạng 2, nên chụp ảnh mã "Mời điện thoại" thì báo
//  "chuỗi khóa không hợp lệ".)
// ==========================================================================
export function parseQr(text) {
  const t = String(text || "").trim();

  // 1) URL lời mời
  const m = t.match(/^https?:\/\/([^/:]+):(\d+)\/join(?:[/?]?)?(?:#(.*))?$/i);
  if (m) {
    const params = new URLSearchParams(m[3] || "");
    return {
      kind: "invite", host: m[1], port: Number(m[2]),
      pub: params.get("k") || null,
      name: params.get("n") || "Máy tính",
      pairCode: params.get("pc") || null,
    };
  }

  // 2) JSON khóa
  if (t.startsWith("{")) {
    try {
      const o = JSON.parse(t);
      if (o.k) return { kind: "key", pub: o.k, name: o.n || "", fp: o.fp || "", pairCode: o.pc || null,
                        host: o.h || null, port: o.p || null };
    } catch { /* rơi xuống dạng khác */ }
  }

  // 3) ip:port
  const m2 = t.match(/^(\d+\.\d+\.\d+\.\d+):(\d+)$/);
  if (m2) return { kind: "address", host: m2[1], port: Number(m2[2]) };

  // 4) khóa công khai trần (điểm nén 33 byte = 66 ký tự hex)
  if (/^0[23][0-9a-f]{64}$/i.test(t)) return { kind: "key", pub: t.toLowerCase(), name: "", pairCode: null };

  return { kind: "unknown", raw: t };
}

// ------------------------------------------------------------ mã hóa at-rest (lưu cục bộ)
/** Bọc một object JSON bằng AES-256-GCM với khóa lưu trữ cục bộ (hex 32 byte).
 *  Dùng cho SQLite/AsyncStorage trên mobile và lịch sử trên web: mở tệp chỉ thấy bản mã. */
export function sealLocal(storageKeyHex, obj) {
  const nonce = randomBytes(12);
  const ct = gcm(hexToBytes(storageKeyHex), nonce).encrypt(te.encode(JSON.stringify(obj)));
  return bytesToHex(nonce) + ":" + bytesToHex(ct);
}

export function openLocal(storageKeyHex, sealed) {
  const [n, c] = String(sealed).split(":");
  const pt = gcm(hexToBytes(storageKeyHex), hexToBytes(n)).decrypt(hexToBytes(c));
  return JSON.parse(td.decode(pt));
}

export function newStorageKey() {
  return bytesToHex(randomBytes(32));
}

export { bytesToHex, hexToBytes, randomBytes, sha256 };
