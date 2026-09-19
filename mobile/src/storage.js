// Lưu trữ cục bộ trên điện thoại (tiêu chí 1 & 2):
//   • Danh tính (khóa bí mật, khóa lưu trữ) → expo-secure-store (Keychain iOS / Keystore Android).
//   • Danh bạ đã ghim + lịch sử tin nhắn → expo-sqlite; nội dung tin nhắn MÃ HÓA AT-REST
//     bằng AES-256-GCM (sealLocal của lõi) với khóa lưu trữ → mở tệp .db chỉ thấy bản mã.
//   • Trên web (chỉ để dev/thử luồng): dùng localStorage thay thế.
import { Platform } from "react-native";
import { genKeypair, fingerprint, sealLocal, openLocal, newStorageKey, bytesToHex, hexToBytes, randomBytes } from "@sentinell/core";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { gcm } from "@noble/ciphers/aes.js";

const IS_WEB = Platform.OS === "web";
let SecureStore = null;
let db = null;

const ID_KEY = "sentinell.identity.v2";

export async function init() {
  if (IS_WEB) return;
  SecureStore = require("expo-secure-store");
  const SQLite = require("expo-sqlite");
  db = SQLite.openDatabaseSync("sentinell.db");
  db.execSync(`
    CREATE TABLE IF NOT EXISTS contacts(fp TEXT PRIMARY KEY, pub TEXT, name TEXT, host TEXT, port INTEGER, pinned_at REAL);
    CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, peer_pub TEXT, direction TEXT, ts REAL, sealed TEXT);
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
  `);
}

// ---------------------------------------------------------------- danh tính
async function readIdentityRaw() {
  if (IS_WEB) {
    try { return JSON.parse(localStorage.getItem(ID_KEY) || "null"); } catch { return null; }
  }
  const s = await SecureStore.getItemAsync(ID_KEY);
  return s ? JSON.parse(s) : null;
}
async function writeIdentityRaw(id) {
  const s = JSON.stringify(id);
  if (IS_WEB) { localStorage.setItem(ID_KEY, s); return; }
  await SecureStore.setItemAsync(ID_KEY, s);
}

/** Ghi danh tính. Có mật khẩu thì KHÔNG BAO GIỜ ghi priv/storage_key bản rõ — chỉ ghi gói
 *  đã bọc bằng khóa dẫn từ mật khẩu (gói được bọc lại nếu priv vừa đổi, ví dụ sau xoay khóa). */
async function persist(id) {
  if (!id.account) { await writeIdentityRaw(id); return; }
  if (!kekMem) throw new Error("Chưa mở khóa");
  const { priv, storage_key, ...congKhai } = id;
  await writeIdentityRaw({ ...congKhai, account: { ...id.account, ...boc(kekMem, { priv, storage_key }) } });
}

export async function loadIdentity() {
  let id = await readIdentityRaw();
  // Có mật khẩu: chỉ trả phần công khai; khóa bí mật phải chờ unlock().
  if (id?.account) return { locked: true, pub: id.pub, name: id.name, account: id.account };
  if (!id) {
    const kp = genKeypair();
    id = {
      priv: kp.priv, pub: kp.pub,
      name: `Điện thoại ${fingerprint(kp.pub).slice(0, 4)}`,
      created: Date.now() / 1000,
      storage_key: newStorageKey(),
    };
    await writeIdentityRaw(id);
  }
  return id;
}

export async function setName(id, name) {
  const n = String(name || "").trim();
  if (!n) return id;
  const next = { ...id, name: n };
  await persist(next);
  return next;
}

// ---------------------------------------------------------------- mật khẩu (tài khoản cục bộ)
// Giống desktop: KEK = scrypt(mật khẩu, muối) → AES-256-GCM bọc { priv, storage_key }. Thẻ GCM
// kiêm luôn việc kiểm mật khẩu: sai mật khẩu ⇒ giải bọc hỏng, không cần lưu băm mật khẩu nào.
// Tham số scrypt LƯU THEO TỪNG TÀI KHOẢN và luôn đọc lại khi mở — bài học của desktop 3.15.0.
let kekMem = null;   // KEK chỉ nằm trong RAM khi đang mở khóa; khóa lại là xóa

export const MAT_KHAU_TOI_THIEU = 8;
const MUC_TIEU_MS = 1500;

function kiemMatKhau(m) {
  if (String(m || "").length < MAT_KHAU_TOI_THIEU) throw new Error(`Mật khẩu phải có ít nhất ${MAT_KHAU_TOI_THIEU} ký tự.`);
}

// scrypt NATIVE (OpenSSL, qua react-native-quick-crypto) — cùng API với crypto.scrypt của Node
// mà desktop đang dùng. Đo trên máy ảo: bản JS thuần (@noble) trên Hermes mất 17,7 s cho mức
// thấp nhất N=2^14 — Hermes không có JIT. Bản native chạy ngoài luồng JS nên giao diện không đơ.
// Không có mô-đun native (web, Expo Go) thì mới lùi về bản JS.
let scryptNative;
function layScryptNative() {
  if (scryptNative !== undefined) return scryptNative;
  try {
    const m = require("react-native-quick-crypto");
    scryptNative = (m.default || m).scrypt || m.scrypt || null;
  } catch { scryptNative = null; }
  return scryptNative;
}

export function kieuKdf() { return layScryptNative() ? "native" : "js"; }

async function danKek(matKhau, saltHex, { N, r, p }, onProgress) {
  const pw = new TextEncoder().encode(String(matKhau));
  const salt = hexToBytes(saltHex);
  const nat = layScryptNative();
  if (nat) {
    onProgress?.(-1);   // native không báo tiến độ → giao diện hiện thanh chạy vô định
    return new Promise((res, rej) => nat(pw, salt, 32, { N, r, p, maxmem: 128 * N * r * 2 }, (e, k) => (e ? rej(e) : res(new Uint8Array(k)))));
  }
  return scryptAsync(pw, salt, { N, r, p, dkLen: 32, onProgress, asyncTick: 20 });
}

function boc(kek, bi) {
  const nonce = randomBytes(12);
  const ct = gcm(kek, nonce).encrypt(new TextEncoder().encode(JSON.stringify(bi)));
  return { nonce: bytesToHex(nonce), ct: bytesToHex(ct) };
}

function moBoc(kek, acc) {
  const pt = gcm(kek, hexToBytes(acc.nonce)).decrypt(hexToBytes(acc.ct));   // sai mật khẩu ⇒ ném lỗi
  return JSON.parse(new TextDecoder().decode(pt));
}

/** Mỗi máy mỗi khác: đo thật trên CHÍNH máy này (N=2^14) rồi chọn N lớn nhất (2^14…2^17) mà
 *  vẫn dẫn khóa trong ~1,5 s. Máy khỏe dùng đúng mức OWASP 2^17 như desktop. */
export async function hieuChinhKdf() {
  const t0 = Date.now();
  await danKek("do-toc-do", "00112233445566778899aabbccddeeff", { N: 16384, r: 8, p: 1 });
  const ms14 = Math.max(1, Date.now() - t0);
  let logN = 14;
  for (let l = 17; l >= 14; l--) {
    if (ms14 * (2 ** (l - 14)) <= MUC_TIEU_MS) { logN = l; break; }
  }
  return { kdf: "scrypt", N: 2 ** logN, r: 8, p: 1, uocTinhMs: Math.round(ms14 * (2 ** (logN - 14))), ms14 };
}

export async function createAccount(id, matKhau, onProgress) {
  kiemMatKhau(matKhau);
  const { uocTinhMs, ms14, ...kdf } = await hieuChinhKdf();
  const salt = bytesToHex(randomBytes(16));
  const t0 = Date.now();
  kekMem = await danKek(matKhau, salt, kdf, onProgress);
  const next = { ...id, account: { ...kdf, salt } };
  await persist(next);
  return { id: next, thongKe: { N: kdf.N, uocTinhMs, thucTeMs: Date.now() - t0 } };
}

/** Mở khóa: dẫn KEK bằng ĐÚNG tham số đã lưu của tài khoản, rồi giải bọc. */
export async function unlock(locked, matKhau, onProgress) {
  const raw = await readIdentityRaw();
  if (!raw?.account) throw new Error("Máy này chưa đặt mật khẩu.");
  const t0 = Date.now();
  const kek = await danKek(matKhau, raw.account.salt, raw.account, onProgress);
  let bi;
  try { bi = moBoc(kek, raw.account); } catch { kek.fill(0); throw new Error("Sai mật khẩu."); }
  kekMem = kek;
  return { id: { ...raw, ...bi }, ms: Date.now() - t0 };
}

export function lock() {
  if (kekMem) kekMem.fill(0);
  kekMem = null;
}

export async function changePassword(id, cu, moi, onProgress) {
  kiemMatKhau(moi);
  const raw = await readIdentityRaw();
  const kekCu = await danKek(cu, raw.account.salt, raw.account, onProgress);
  try { moBoc(kekCu, raw.account); } catch { throw new Error("Mật khẩu hiện tại không đúng."); }
  const { uocTinhMs, ms14, ...kdf } = await hieuChinhKdf();
  const salt = bytesToHex(randomBytes(16));
  kekMem = await danKek(moi, salt, kdf, onProgress);
  const next = { ...id, account: { ...kdf, salt } };
  await persist(next);
  return next;
}

/** Bỏ mật khẩu: khóa quay về chỉ được Keystore của Android bảo vệ. */
export async function removeAccount(id, matKhau, onProgress) {
  const raw = await readIdentityRaw();
  const kek = await danKek(matKhau, raw.account.salt, raw.account, onProgress);
  try { moBoc(kek, raw.account); } catch { throw new Error("Sai mật khẩu."); }
  const { account, ...rest } = id;
  lock();
  await writeIdentityRaw(rest);
  return rest;
}

// ---------------------------------------------------------------- cài đặt & mã nút
/** Mã nút ngẫu nhiên, cố định cho máy này — dùng làm `id` trong quảng bá mDNS. */
export async function nodeId() {
  let v = await getMeta("node_id", null);
  if (!v) { v = bytesToHex(randomBytes(16)); await setMeta("node_id", v); }
  return v;
}

export async function getStrict() { return !!(await getMeta("strict", false)); }
export async function setStrict(v) { await setMeta("strict", !!v); }

/** Xoay khóa: khóa cũ lưu vào meta.archived, sinh khóa mới; giữ storage_key để đọc lịch sử. */
export async function rotateIdentity(id) {
  const archived = await getMeta("archived", []);
  archived.push({ pub: id.pub, retired: Date.now() / 1000 });
  await setMeta("archived", archived);
  const kp = genKeypair();
  const next = { ...id, priv: kp.priv, pub: kp.pub, created: Date.now() / 1000 };
  await persist(next);   // có mật khẩu thì khóa mới được bọc lại bằng KEK đang mở
  return next;
}

export async function archivedCount() {
  return (await getMeta("archived", [])).length;
}

// ---------------------------------------------------------------- meta
async function getMeta(k, dflt) {
  if (IS_WEB) { try { return JSON.parse(localStorage.getItem("sentinell.meta." + k)) ?? dflt; } catch { return dflt; } }
  const row = db.getFirstSync("SELECT v FROM meta WHERE k=?", [k]);
  return row ? JSON.parse(row.v) : dflt;
}
async function setMeta(k, v) {
  if (IS_WEB) { localStorage.setItem("sentinell.meta." + k, JSON.stringify(v)); return; }
  db.runSync("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", [k, JSON.stringify(v)]);
}

// ---------------------------------------------------------------- danh bạ (khóa đã ghim)
/** Ghim khóa công khai của một thiết bị; kèm địa chỉ lần gặp gần nhất để kết nối lại nhanh. */
export async function pinContact(pub, name = "", host = null, port = null) {
  const fp = fingerprint(pub);
  const existing = await contactByPub(pub);
  const finalName = name || existing?.name || `Liên hệ ${fp.slice(0, 6)}`;
  const finalHost = host ?? existing?.host ?? null;
  const finalPort = port ?? existing?.port ?? null;
  const row = { pub, name: finalName, host: finalHost, port: finalPort, pinned_at: Date.now() / 1000 };
  if (IS_WEB) {
    const all = JSON.parse(localStorage.getItem("sentinell.contacts") || "{}");
    all[fp] = row;
    localStorage.setItem("sentinell.contacts", JSON.stringify(all));
  } else {
    db.runSync("INSERT OR REPLACE INTO contacts(fp,pub,name,host,port,pinned_at) VALUES(?,?,?,?,?,?)",
      [fp, pub, finalName, finalHost, finalPort, row.pinned_at]);
  }
  return { fingerprint: fp, ...row };
}

export async function listContacts() {
  if (IS_WEB) {
    const all = JSON.parse(localStorage.getItem("sentinell.contacts") || "{}");
    return Object.entries(all).map(([fingerprint, c]) => ({ fingerprint, ...c }));
  }
  return db.getAllSync("SELECT fp AS fingerprint, pub, name, host, port, pinned_at FROM contacts ORDER BY pinned_at DESC");
}

export async function contactByPub(pub) {
  const fp = fingerprint(pub);
  const all = await listContacts();
  return all.find((c) => c.fingerprint === fp) || null;
}

// ---------------------------------------------------------------- tin nhắn (mã hóa at-rest)
export async function saveMessage(id, peerPub, direction, body) {
  const ts = Date.now() / 1000;
  const sealed = sealLocal(id.storage_key, body);
  if (IS_WEB) {
    const key = "sentinell.msgs." + fingerprint(peerPub);
    const arr = JSON.parse(localStorage.getItem(key) || "[]");
    arr.push({ direction, ts, sealed });
    localStorage.setItem(key, JSON.stringify(arr.slice(-300)));
  } else {
    db.runSync("INSERT INTO messages(peer_pub,direction,ts,sealed) VALUES(?,?,?,?)", [peerPub, direction, ts, sealed]);
  }
  return ts;
}

export async function loadHistory(id, peerPub, limit = 200) {
  let rows;
  if (IS_WEB) {
    rows = JSON.parse(localStorage.getItem("sentinell.msgs." + fingerprint(peerPub)) || "[]").slice(-limit);
  } else {
    rows = db.getAllSync(
      "SELECT direction, ts, sealed FROM messages WHERE peer_pub=? ORDER BY id DESC LIMIT ?", [peerPub, limit]).reverse();
  }
  return rows.map((r) => {
    let body;
    try { body = openLocal(id.storage_key, r.sealed); }
    catch { body = { type: "text", text: "<không giải mã được lịch sử>" }; }
    return { direction: r.direction, ts: r.ts, body };
  });
}
