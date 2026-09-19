// Lưu trữ cục bộ trên máy — port từ reference/python/sentinell/storage.py.
//   • identity.json : khóa danh tính + khóa lưu trữ. Khi chạy trong Electron, khóa bí mật
//                     được BỌC thêm bằng safeStorage (Windows DPAPI / macOS Keychain).
//   • contacts.json : khóa công khai của peer đã ghim qua QR.
//   • messages.db   : SQLite (sql.js, WASM — không cần biên dịch native), nội dung tin
//                     nhắn MÃ HÓA AT-REST bằng AES-256-GCM với khóa lưu trữ cục bộ.
//   • files/        : file/ảnh đã gửi/nhận.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { genKeypair, fingerprint } from "@sentinell/core";

const require = createRequire(import.meta.url);
const initSqlJs = require("sql.js");

export class Storage {
  /** protect: {encrypt(str)->str, decrypt(str)->str} | null (không có Electron). */
  static async open(dataDir, protect = null) {
    const s = new Storage(dataDir, protect);
    await s._init();
    return s;
  }

  constructor(dataDir, protect) {
    this.dir = dataDir;
    this.protect = protect;
    fs.mkdirSync(this.dir, { recursive: true });
    this.filesDir = path.join(this.dir, "files");
    fs.mkdirSync(this.filesDir, { recursive: true });
    this.identityPath = path.join(this.dir, "identity.json");
    this.contactsPath = path.join(this.dir, "contacts.json");
    this.trashPath = path.join(this.dir, "trash.json");
    this.knownPath = path.join(this.dir, "known.json");
    this.dbPath = path.join(this.dir, "messages.db");
  }

  async _init() {
    this.locked = false;
    this._loadIdentity();
    this._loadContacts();
    this._loadTrash();
    this._loadKnown();
    // Còn khóa thì chưa có khóa lưu trữ để mở kho tin nhắn — đợi mật khẩu đã.
    if (!this.locked) await this._initDb();
  }

  get hasAccount() { return !!this.identity?.account; }

  // ---------------------------------------------------------------- danh tính
  _wrap(s) { return this.protect ? this.protect.encrypt(s) : s; }
  _unwrap(s) { return this.protect ? this.protect.decrypt(s) : s; }

  _loadIdentity() {
    if (fs.existsSync(this.identityPath)) {
      const raw = JSON.parse(fs.readFileSync(this.identityPath, "utf8"));
      if (raw.account) {
        // CÓ TÀI KHOẢN: khóa bí mật và khóa lưu trữ chỉ tồn tại bên trong `account.ct`,
        // mở được bằng mật khẩu. Trên đĩa không còn bản rõ nào để mà đọc.
        this.identity = {
          pub: raw.pub, name: raw.name, created: raw.created,
          archived: raw.archived || [], account: raw.account,
        };
        this.locked = true;
        return;
      }
      // trên đĩa: priv/storage_key có thể đã được bọc bởi safeStorage
      this.identity = {
        ...raw,
        priv: raw.protected ? this._unwrap(raw.priv) : raw.priv,
        storage_key: raw.protected ? this._unwrap(raw.storage_key) : raw.storage_key,
      };
      delete this.identity.protected;
      return;
    }
    const kp = genKeypair();
    this.identity = {
      priv: kp.priv,
      pub: kp.pub,
      name: `Thiết bị ${fingerprint(kp.pub).slice(0, 6)}`,
      created: Date.now() / 1000,
      storage_key: crypto.randomBytes(32).toString("hex"),
      archived: [],
    };
    this._saveIdentity();
  }

  _saveIdentity() {
    if (this.identity.account) {
      // Bản rõ chỉ nằm trong RAM khi đã mở khóa — tuyệt đối không ghi xuống đĩa.
      const { priv, storage_key, ...cong } = this.identity;
      fs.writeFileSync(this.identityPath, JSON.stringify(cong, null, 2), "utf8");
      return;
    }
    const onDisk = {
      ...this.identity,
      priv: this._wrap(this.identity.priv),
      storage_key: this._wrap(this.identity.storage_key),
      protected: !!this.protect,
    };
    fs.writeFileSync(this.identityPath, JSON.stringify(onDisk, null, 2), "utf8");
  }

  get idPriv() { return this.identity.priv; }
  get idPub() { return this.identity.pub; }
  get name() { return this.identity.name; }

  /** Cài đặt người dùng (lưu trong settings.json cạnh danh bạ). */
  get settings() {
    if (!this._settings) {
      const p = this.settingsPath;
      this._settings = fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : { strictMode: false };
    }
    return this._settings;
  }
  get settingsPath() { return path.join(this.dir, "settings.json"); }
  setSetting(key, value) {
    const s = this.settings;
    s[key] = value;
    fs.writeFileSync(this.settingsPath, JSON.stringify(s, null, 2), "utf8");
    return s;
  }

  setName(name) {
    const n = String(name || "").trim();
    if (n) this.identity.name = n;
    this._saveIdentity();
  }

  /** Xoay khóa: lưu khóa cũ, sinh khóa mới; giữ storage_key để vẫn đọc được lịch sử. */
  rotateIdentity() {
    this.identity.archived.push({ pub: this.identity.pub, retired: Date.now() / 1000 });
    const kp = genKeypair();
    this.identity.priv = kp.priv;
    this.identity.pub = kp.pub;
    this.identity.created = Date.now() / 1000;
    // Khóa bí mật vừa đổi → gói tài khoản đang giữ khóa CŨ, phải bọc lại,
    // nếu không lần mở app sau sẽ lấy ra đúng cái khóa vừa bị thay.
    if (this.hasAccount) this._boclaiTaiKhoan();
    this._saveIdentity();
    return { pub: kp.pub, fingerprint: fingerprint(kp.pub) };
  }

  exportPublic() {
    return { k: this.idPub, n: this.name, fp: fingerprint(this.idPub) };
  }

  // ====================================================================
  // TÀI KHOẢN CỤC BỘ (mật khẩu)
  //
  // Không có tài khoản: khóa bí mật nằm trên đĩa, chỉ được safeStorage (DPAPI) bọc lại.
  // DPAPI gắn với TÀI KHOẢN WINDOWS — ai đã đăng nhập vào máy này là mở được, và chép
  // tệp sang máy khác thì mất luôn. Đặt mật khẩu sẽ đổi hẳn cách bảo vệ:
  //
  //   mật khẩu --scrypt(N=2^15, r=8, p=1, salt 16B)--> KEK 32B
  //   account.ct = AES-256-GCM(KEK, {priv, storage_key})
  //
  // scrypt cố ý tốn cả thời gian LẪN bộ nhớ (~32 MB mỗi lần thử) nên dò mật khẩu hàng
  // loạt bằng GPU trở nên rất đắt [GT 4.1 — hàm dẫn xuất khóa từ mật khẩu]. Thẻ xác thực
  // của GCM đóng luôn vai trò kiểm mật khẩu: sai mật khẩu thì giải mã thất bại, không
  // cần lưu thêm "giá trị kiểm tra" nào (thứ chỉ tổ giúp kẻ dò thử nhanh hơn).
  //
  // Mở khóa xong thì KEK được giữ trong RAM để còn bọc lại khi xoay khóa hay đổi tên,
  // và bị xóa khi khóa lại.
  // ====================================================================
  // N = 2^17 theo khuyến nghị của OWASP cho scrypt (r=8, p=1) — tốn 128 MB và ~0,5 giây
  // mỗi lần thử, đủ để việc dò hàng loạt bằng GPU trở nên rất đắt. (Đo trên máy thật:
  // 2^15 → 115 ms, 2^16 → 232 ms, 2^17 → 468 ms.)
  static get KDF() { return { kdf: "scrypt", N: 131072, r: 8, p: 1 }; }

  /** Dẫn khóa từ mật khẩu.
   *
   *  PHẢI dùng tham số ĐÃ LƯU trong gói tài khoản, không phải tham số hiện hành: tài khoản
   *  tạo bằng bản cũ có N nhỏ hơn, mà cứ dẫn bằng N mới thì ra khóa khác ⇒ mở không được
   *  nữa, mất sạch. (Trước 3.15.0 các trường N/r/p vẫn được GHI vào tệp nhưng chẳng bao giờ
   *  đọc lại — nghĩa là tham số bị đóng băng vĩnh viễn, đụng vào là khóa chết mọi tài khoản
   *  đã tạo.) Tạo tài khoản mới thì mới dùng tham số hiện hành. */
  _dansuatKek(matKhau, saltHex, thamSo = null) {
    const N = thamSo?.N || Storage.KDF.N;
    const r = thamSo?.r || Storage.KDF.r;
    const p = thamSo?.p || Storage.KDF.p;
    return crypto.scryptSync(
      Buffer.from(String(matKhau), "utf8"), Buffer.from(saltHex, "hex"), 32,
      // maxmem phải ≥ 128·N·r, nếu không Node ném lỗi thay vì chạy.
      { N, r, p, maxmem: Math.max(96, (128 * N * r) / 1048576 * 2) * 1024 * 1024 },
    );
  }

  /** Gói {priv, storage_key} bằng một KEK + salt cho trước.
   *  `kdf` phải là ĐÚNG bộ tham số đã dẫn ra `kek` — ghi tham số mới trong khi bản mã lại
   *  do KEK của tham số cũ tạo ra là lần mở sau không tài nào ra đúng khóa. */
  _taoGoi(kek, salt, kdf = Storage.KDF) {
    const nonce = crypto.randomBytes(12);
    const c = crypto.createCipheriv("aes-256-gcm", kek, nonce);
    const ct = Buffer.concat([
      c.update(JSON.stringify({ priv: this.identity.priv, storage_key: this.identity.storage_key }), "utf8"),
      c.final(), c.getAuthTag(),
    ]);
    return { ...kdf, salt, nonce: nonce.toString("hex"), ct: ct.toString("hex") };
  }

  /** Bọc lại bằng KEK đang giữ. Gọi sau mỗi lần khóa bí mật đổi. */
  _boclaiTaiKhoan() {
    if (!this._kek) throw new Error("Chưa mở khóa");
    this.identity.account = this._taoGoi(this._kek, this.identity.account.salt, this._kdf || Storage.KDF);
  }

  static _moGoi(kek, acc) {
    const buf = Buffer.from(acc.ct, "hex");
    const tag = buf.subarray(buf.length - 16), data = buf.subarray(0, buf.length - 16);
    const d = crypto.createDecipheriv("aes-256-gcm", kek, Buffer.from(acc.nonce, "hex"));
    d.setAuthTag(tag);
    return JSON.parse(Buffer.concat([d.update(data), d.final()]).toString("utf8"));
  }

  /** Đặt mật khẩu cho máy này. Từ lần mở app sau, phải nhập mới dùng được. */
  async createAccount(matKhau) {
    if (this.locked) throw new Error("Đang khóa");
    if (this.hasAccount) throw new Error("Máy này đã có tài khoản rồi");
    kiemTraMatKhau(matKhau);
    const salt = crypto.randomBytes(16).toString("hex");
    this.identity.account = { ...Storage.KDF, salt, nonce: "", ct: "" };
    this._kdf = Storage.KDF;
    this._kek = this._dansuatKek(matKhau, salt);
    this._boclaiTaiKhoan();
    this._saveIdentity();
    return { pub: this.idPub, name: this.name };
  }

  /** Mở khóa bằng mật khẩu. Sai mật khẩu → GCM từ chối, ném lỗi. */
  async unlock(matKhau) {
    if (!this.hasAccount) return true;
    if (!this.locked) return true;
    const kek = this._dansuatKek(matKhau, this.identity.account.salt, this.identity.account);
    let bimat;
    try {
      bimat = Storage._moGoi(kek, this.identity.account);
    } catch {
      throw new Error("Mật khẩu không đúng.");
    }
    this._kek = kek;
    this._kdf = { N: this.identity.account.N, r: this.identity.account.r, p: this.identity.account.p };
    this.identity.priv = bimat.priv;
    this.identity.storage_key = bimat.storage_key;
    this.locked = false;
    await this._initDb();
    return true;
  }

  /** Khóa lại ngay: xóa bí mật khỏi RAM, đóng kho tin nhắn. */
  lock() {
    if (!this.hasAccount) return false;
    this.identity.priv = undefined;
    this.identity.storage_key = undefined;
    this._kek = undefined;
    this._kdf = undefined;
    try { this.db?.close(); } catch { /* */ }
    this.db = null;
    this.locked = true;
    return true;
  }

  async changePassword(cu, moi) {
    if (!this.hasAccount || this.locked) throw new Error("Chưa mở khóa");
    kiemTraMatKhau(moi);
    try {
      Storage._moGoi(this._dansuatKek(cu, this.identity.account.salt, this.identity.account), this.identity.account);
    } catch {
      throw new Error("Mật khẩu hiện tại không đúng.");
    }
    const salt = crypto.randomBytes(16).toString("hex");
    // Đổi mật khẩu cũng là dịp NÂNG tham số lên mức hiện hành.
    this.identity.account = { ...this.identity.account, ...Storage.KDF, salt };
    this._kdf = Storage.KDF;
    this._kek = this._dansuatKek(moi, salt);
    this._boclaiTaiKhoan();
    this._saveIdentity();
  }

  /** Bỏ mật khẩu, quay lại cách bảo vệ bằng safeStorage của hệ điều hành. */
  async removeAccount(matKhau) {
    if (!this.hasAccount || this.locked) throw new Error("Chưa mở khóa");
    try {
      Storage._moGoi(this._dansuatKek(matKhau, this.identity.account.salt, this.identity.account), this.identity.account);
    } catch {
      throw new Error("Mật khẩu không đúng.");
    }
    delete this.identity.account;
    this._kek = undefined;
    this._saveIdentity();
  }

  /** Tệp sao lưu / chuyển máy. Khóa bí mật LUÔN nằm trong gói scrypt+GCM — tệp rơi
   *  vào tay người khác thì vẫn phải có mật khẩu mới mở được.
   *
   *  Máy chưa đặt mật khẩu vẫn sao lưu được: nhập một mật khẩu riêng cho tệp này thôi,
   *  không biến nó thành tài khoản của máy. (Trước 3.10.0 có một nút "Sao lưu" xuất
   *  khóa bí mật dạng BẢN RÕ — đặt mật khẩu cho app xong rồi mà một cú bấm là lộ sạch
   *  thì coi như không đặt. Nút đó đã bỏ.) */
  exportAccount(matKhau = null) {
    if (this.locked) throw new Error("Chưa mở khóa");
    let acc;
    if (this.hasAccount) {
      acc = this.identity.account;
    } else {
      kiemTraMatKhau(matKhau);
      const salt = crypto.randomBytes(16).toString("hex");
      acc = this._taoGoi(this._dansuatKek(matKhau, salt), salt, Storage.KDF);
    }
    return {
      kind: "sentinell-account", v: 1, exported: Date.now() / 1000,
      pub: this.identity.pub, name: this.identity.name, created: this.identity.created,
      archived: this.identity.archived || [],
      account: acc,
      contacts: this.contacts,
    };
  }

  /** Nhận tài khoản từ tệp (trên máy mới). Phải đúng mật khẩu mới ghi đè danh tính. */
  async importAccount(data, matKhau) {
    if (!data || data.kind !== "sentinell-account" || !data.account?.ct) {
      throw new Error("Tệp không phải tài khoản Sentinell.");
    }
    let bimat;
    try {
      bimat = Storage._moGoi(this._dansuatKek(matKhau, data.account.salt, data.account), data.account);
    } catch {
      throw new Error("Mật khẩu không mở được tệp này.");
    }
    this.identity = {
      pub: data.pub, name: data.name, created: data.created || Date.now() / 1000,
      archived: data.archived || [], account: data.account,
      priv: bimat.priv, storage_key: bimat.storage_key,
    };
    this._kek = this._dansuatKek(matKhau, data.account.salt, data.account);
    this._kdf = { N: data.account.N, r: data.account.r, p: data.account.p };
    this.contacts = data.contacts || {};
    this._saveContacts();
    this._saveIdentity();
    this.locked = false;
    await this._initDb();
    return { name: this.identity.name, contacts: Object.keys(this.contacts).length };
  }

  /** Sao lưu TOÀN BỘ danh tính (bản rõ, gồm khóa bí mật) — người dùng tự giữ. */
  exportBackup() {
    const { account, ...rest } = this.identity;
    return { ...rest };
  }

  importBackup(data) {
    for (const k of ["priv", "pub", "storage_key"]) {
      if (!data[k]) throw new Error("Tệp sao lưu không hợp lệ");
    }
    this.identity = {
      priv: data.priv, pub: data.pub,
      name: data.name || this.identity.name,
      created: data.created || Date.now() / 1000,
      storage_key: data.storage_key,
      archived: data.archived || [],
      // Máy này đang đặt mật khẩu thì giữ nguyên tài khoản, chỉ bọc lại khóa vừa nhập.
      account: this.identity.account,
    };
    if (this.hasAccount) this._boclaiTaiKhoan();
    this._saveIdentity();
  }

  // ---------------------------------------------------------------- danh bạ
  _loadContacts() {
    this.contacts = fs.existsSync(this.contactsPath)
      ? JSON.parse(fs.readFileSync(this.contactsPath, "utf8")) : {};
  }
  _saveContacts() {
    fs.writeFileSync(this.contactsPath, JSON.stringify(this.contacts, null, 2), "utf8");
  }
  /** Ghim khóa công khai của một thiết bị, kèm ĐỊA CHỈ gặp gần nhất để còn gọi lại được. */
  pinContact(pub, name = "", host = null, port = null) {
    const fp = fingerprint(pub);
    const prev = this.contacts[fp] || {};
    this.contacts[fp] = {
      pub,
      name: name || prev.name || `Liên hệ ${fp.slice(0, 6)}`,
      host: host ?? prev.host ?? null,
      port: port ?? prev.port ?? null,
      pinned_at: prev.pinned_at || Date.now() / 1000,
      last_seen: Date.now() / 1000,
    };
    this._saveContacts();
    return this.contacts[fp];
  }
  contactByPub(pub) { return this.contacts[fingerprint(pub)] || null; }
  listContacts() {
    return Object.entries(this.contacts).map(([fingerprint, c]) => ({ fingerprint, ...c }));
  }

  /** Bỏ ghim một liên hệ (dùng khi xóa cuộc trò chuyện). */
  removeContact(fp) {
    if (!fp || !this.contacts[fp]) return false;
    delete this.contacts[fp];
    this._saveContacts();
    return true;
  }

  // ------------------------------------------------- thiết bị đã từng nói chuyện
  //
  // Danh bạ chỉ chứa khóa ĐÃ GHIM qua QR. Nhưng ta còn nhắn được với thiết bị chưa
  // ghim (họ gọi sang, mình bấm Chấp nhận) — những cuộc đó vẫn có lịch sử lưu trên
  // máy. Trước đây cột trò chuyện dựng từ danh bạ nên các cuộc ấy BIẾN MẤT khỏi
  // danh sách trong khi tìm kiếm vẫn moi ra được: nhìn như app tự nhớ những thứ
  // người dùng tưởng đã không còn. Nên phải ghi lại tên của mọi thiết bị từng nói
  // chuyện, tách riêng với chuyện đã ghim khóa hay chưa.
  _loadKnown() {
    this.known = fs.existsSync(this.knownPath)
      ? JSON.parse(fs.readFileSync(this.knownPath, "utf8")) : {};
  }
  _saveKnown() {
    fs.writeFileSync(this.knownPath, JSON.stringify(this.known, null, 2), "utf8");
  }

  rememberPeer(pub, name = "", host = null, port = null) {
    if (!pub) return null;
    const fp = fingerprint(pub);
    const cu = this.known[fp] || {};
    this.known[fp] = {
      pub,
      name: name || cu.name || `Thiết bị ${fp.slice(0, 6)}`,
      host: host ?? cu.host ?? null,
      port: port ?? cu.port ?? null,
      last_seen: Date.now() / 1000,
    };
    this._saveKnown();
    return this.known[fp];
  }
  forgetPeer(fp) {
    if (!fp || !this.known[fp]) return false;
    delete this.known[fp];
    this._saveKnown();
    return true;
  }

  /** Mọi cuộc trò chuyện đáng hiện lên cột bên trái: đã ghim khóa, HOẶC còn lịch sử.
   *  Đây mới là thứ giao diện cần — `listContacts()` chỉ nói về khóa đã ghim. */
  listConversations() {
    const ra = new Map();
    for (const c of this.listContacts()) {
      ra.set(c.fingerprint, { ...c, pinned: true });
    }
    for (const [fp, k] of Object.entries(this.known)) {
      if (ra.has(fp) || this._demTin(k.pub, false) === 0) continue;
      ra.set(fp, { fingerprint: fp, ...k, pinned: false });
    }
    // Lịch sử còn sót của thiết bị chưa kịp ghi tên (kho từ bản cũ) — vẫn phải hiện,
    // nếu không thì lại rơi vào đúng cái bẫy "tìm thấy mà không mở được".
    for (const pub of this._cacPeerCoLichSu()) {
      const fp = fingerprint(pub);
      if (ra.has(fp)) continue;
      ra.set(fp, {
        fingerprint: fp, pub, name: `Thiết bị ${fp.slice(0, 6)}`,
        host: null, port: null, pinned: false, last_seen: 0,
      });
    }
    return [...ra.values()];
  }

  _cacPeerCoLichSu() {
    const r = this.db.exec("SELECT DISTINCT peer_pub FROM messages WHERE deleted_at IS NULL");
    return (r[0]?.values || []).map((v) => v[0]).filter(Boolean);
  }

  // ---------------------------------------------------------------- tin nhắn
  async _initDb() {
    const SQL = await initSqlJs({
      locateFile: (f) => require.resolve(`sql.js/dist/${f}`),
    });
    this.db = fs.existsSync(this.dbPath)
      ? new SQL.Database(fs.readFileSync(this.dbPath))
      : new SQL.Database();
    this.db.run(`CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      peer_pub TEXT, direction TEXT, ts REAL, nonce BLOB, body_ct BLOB,
      deleted_at REAL)`);
    // Kho cũ (trước 3.9.0) chưa có cột này — thêm vào, nếu không mọi truy vấn đều lỗi.
    const cot = this.db.exec("PRAGMA table_info(messages)");
    const ten = (cot[0]?.values || []).map((r) => r[1]);
    if (!ten.includes("deleted_at")) this.db.run("ALTER TABLE messages ADD COLUMN deleted_at REAL");
    this._flush();
  }
  _flush() {
    fs.writeFileSync(this.dbPath, Buffer.from(this.db.export()));
  }
  _skey() { return Buffer.from(this.identity.storage_key, "hex"); }

  saveMessage(peerPub, direction, body, ts = null) {
    ts = ts ?? Date.now() / 1000;
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this._skey(), nonce);
    const ct = Buffer.concat([cipher.update(JSON.stringify(body), "utf8"), cipher.final(), cipher.getAuthTag()]);
    this.db.run(
      "INSERT INTO messages(peer_pub,direction,ts,nonce,body_ct) VALUES(?,?,?,?,?)",
      [peerPub, direction, ts, nonce, ct],
    );
    this._flush();
    return ts;
  }

  /** Tin nhắn mới nhất của một liên hệ — danh sách trò chuyện cần dòng xem trước này. */
  lastMessage(peerPub) {
    const rows = this.loadHistory(peerPub, 1);
    if (!rows.length) return null;
    const { direction, ts, body } = rows[0];
    let preview;
    if (body.type === "file") {
      preview = (body.mime || "").startsWith("image/") ? "📷 Ảnh" : `📎 ${body.name || "Tệp"}`;
    } else {
      preview = String(body.text || "");
    }
    return { direction, ts, preview: preview.slice(0, 90) };
  }

  /** Giải mã phần thân một dòng. Trả null nếu hỏng (đổi khóa, tệp .db bị sửa…). */
  _openBody(nonce, ct) {
    try {
      const buf = Buffer.from(ct);
      const tag = buf.subarray(buf.length - 16), data = buf.subarray(0, buf.length - 16);
      const d = crypto.createDecipheriv("aes-256-gcm", this._skey(), Buffer.from(nonce));
      d.setAuthTag(tag);
      return JSON.parse(Buffer.concat([d.update(data), d.final()]).toString("utf8"));
    } catch {
      return null;
    }
  }

  loadHistory(peerPub, limit = 200) {
    const stmt = this.db.prepare(
      "SELECT direction,ts,nonce,body_ct FROM messages WHERE peer_pub=? AND deleted_at IS NULL ORDER BY id DESC LIMIT ?");
    stmt.bind([peerPub, limit]);
    const rows = [];
    while (stmt.step()) rows.push(stmt.get());
    stmt.free();
    const out = [];
    for (const [direction, ts, nonce, ct] of rows.reverse()) {
      const body = this._openBody(nonce, ct) || { type: "text", text: "<không giải mã được lịch sử>" };
      out.push({ direction, ts, body });
    }
    return out;
  }

  /** Bỏ dấu + hạ chữ thường, để gõ "bao cao" vẫn tìm ra "Báo cáo". */
  static khongDau(s) {
    return String(s ?? "")
      .normalize("NFD").replace(/[̀-ͯ]/g, "")   // tách dấu thanh/dấu mũ rồi bỏ
      .replace(/đ/g, "d").replace(/Đ/g, "D")              // đ không phải chữ có dấu tách được
      .toLowerCase();
  }

  /** Tìm trong nội dung tin nhắn.
   *
   *  Không dùng `LIKE` của SQL được: nội dung nằm trong cột `body_ct` đã MÃ HÓA AT-REST,
   *  trong tệp .db chỉ là bytes ngẫu nhiên. Vậy nên phải giải mã từng dòng rồi so trong
   *  bộ nhớ — chậm hơn, nhưng đó chính là cái giá (và là mục đích) của việc mã hóa kho:
   *  ai lấy được tệp .db cũng không tìm kiếm được gì trong đó.
   *
   *  Quét từ MỚI về CŨ và dừng khi đủ `limit` kết quả, nên phần lớn lần tìm không phải
   *  đụng tới toàn bộ lịch sử. */
  searchMessages(query, { limit = 60, peerPub = null } = {}) {
    const q = Storage.khongDau(query).trim();
    if (!q) return { items: [], scanned: 0, truncated: false };

    // `deleted_at IS NULL`: tin đã xóa nằm trong mục "Đã xóa" và KHÔNG được tìm ra —
    // xóa rồi mà gõ vài chữ lại lòi ra thì coi như chưa xóa.
    const stmt = this.db.prepare(peerPub
      ? "SELECT peer_pub,direction,ts,nonce,body_ct FROM messages WHERE peer_pub=? AND deleted_at IS NULL ORDER BY id DESC"
      : "SELECT peer_pub,direction,ts,nonce,body_ct FROM messages WHERE deleted_at IS NULL ORDER BY id DESC");
    if (peerPub) stmt.bind([peerPub]);

    const items = [];
    let scanned = 0, truncated = false;
    while (stmt.step()) {
      scanned++;
      const [pub, direction, ts, nonce, ct] = stmt.get();
      const body = this._openBody(nonce, ct);
      if (!body) continue;
      const day = body.type === "file" ? (body.name || "") : (body.text || "");
      const chuan = Storage.khongDau(day);
      const vt = chuan.indexOf(q);
      if (vt < 0) continue;
      items.push({
        peer_pub: pub, direction, ts,
        kind: body.type || "text",
        mime: body.mime || "",
        text: catQuanh(day, chuan, vt, q.length),
      });
      if (items.length >= limit) { truncated = true; break; }
    }
    stmt.free();
    return { items, scanned, truncated };
  }

  // ------------------------------------------------------------- mục "Đã xóa"
  //
  // Xóa cuộc trò chuyện KHÔNG xóa thẳng nữa: đánh dấu `deleted_at` rồi cất thông tin
  // liên hệ sang trash.json. Mọi truy vấn thường (lịch sử, xem trước, TÌM KIẾM) đều
  // lọc `deleted_at IS NULL`, nên thứ đã xóa không còn lối nào lọt trở lại giao diện
  // ngoài đúng mục "Đã xóa".
  _loadTrash() {
    this.trash = fs.existsSync(this.trashPath)
      ? JSON.parse(fs.readFileSync(this.trashPath, "utf8")) : {};
  }
  _saveTrash() {
    fs.writeFileSync(this.trashPath, JSON.stringify(this.trash, null, 2), "utf8");
  }

  /** Chuyển một cuộc trò chuyện vào mục Đã xóa. Trả về số tin đã chuyển. */
  trashChat(peerPub, name = "") {
    const fp = fingerprint(peerPub);
    const c = this.contacts[fp] || this.known[fp] || null;
    const luc = Date.now() / 1000;
    this.db.run("UPDATE messages SET deleted_at=? WHERE peer_pub=? AND deleted_at IS NULL", [luc, peerPub]);
    const so = this._demTin(peerPub, true);
    this._flush();

    const cu = this.trash[fp];
    this.trash[fp] = {
      pub: peerPub,
      name: name || c?.name || cu?.name || `Liên hệ ${fp.slice(0, 6)}`,
      host: c?.host ?? cu?.host ?? null,
      port: c?.port ?? cu?.port ?? null,
      // Khóa này CÓ được ghim qua QR hay không — khôi phục phải trả lại đúng trạng thái
      // ấy, chứ không tự dưng phong cho một liên hệ chưa xác minh thành đã xác minh.
      was_pinned: !!this.contacts[fp] || !!cu?.was_pinned,
      deleted_at: luc,
    };
    this._saveTrash();
    this.removeContact(fp);
    this.forgetPeer(fp);     // gỡ khỏi cột trò chuyện, nếu không nó vẫn đứng đó
    return so;
  }

  /** Đưa một cuộc trò chuyện từ mục Đã xóa trở lại. */
  restoreChat(fp) {
    const t = this.trash[fp];
    if (!t) return null;
    this.db.run("UPDATE messages SET deleted_at=NULL WHERE peer_pub=?", [t.pub]);
    this._flush();
    if (t.was_pinned) this.pinContact(t.pub, t.name, t.host, t.port);
    else this.rememberPeer(t.pub, t.name, t.host, t.port);   // chưa ghim vẫn phải quay lại cột
    delete this.trash[fp];
    this._saveTrash();
    return t;
  }

  /** Xóa vĩnh viễn: lúc này mới thật sự DELETE khỏi kho, không lấy lại được nữa. */
  purgeChat(fp) {
    const t = this.trash[fp];
    if (!t) return null;
    this.db.run("DELETE FROM messages WHERE peer_pub=? AND deleted_at IS NOT NULL", [t.pub]);
    this._dondep();
    this._flush();
    delete this.trash[fp];
    this._saveTrash();
    return t;
  }

  /** DELETE của SQLite chỉ đánh dấu trang là trống chứ KHÔNG xóa bytes — khóa công khai
   *  của người kia, mốc thời gian và cả bản mã vẫn nằm nguyên trong tệp .db cho tới khi
   *  bị ghi đè. Nội dung thì đã mã hóa, nhưng "đã nói chuyện với ai, lúc nào, bao nhiêu
   *  tin" là siêu dữ liệu, mà siêu dữ liệu cũng là thứ cần giấu. VACUUM dựng lại tệp,
   *  bỏ hẳn phần trống đó đi — có thế mới gọi là xóa vĩnh viễn. */
  _dondep() {
    try { this.db.run("VACUUM"); } catch { /* không dọn được thì thôi, dữ liệu vẫn đã xóa */ }
  }

  _demTin(peerPub, daXoa) {
    const r = this.db.exec(
      `SELECT COUNT(*) FROM messages WHERE peer_pub=? AND deleted_at IS ${daXoa ? "NOT NULL" : "NULL"}`,
      [peerPub]);
    return r[0]?.values?.[0]?.[0] || 0;
  }

  /** Danh sách trong mục Đã xóa, mới xóa xếp trước. */
  listTrash() {
    return Object.entries(this.trash)
      .map(([fp, t]) => ({ fingerprint: fp, ...t, count: this._demTin(t.pub, true) }))
      .sort((a, b) => (b.deleted_at || 0) - (a.deleted_at || 0));
  }

  clearHistory(peerPub) {
    this.db.run("DELETE FROM messages WHERE peer_pub=?", [peerPub]);
    this._dondep();
    this._flush();
  }
}

/** Mật khẩu quá ngắn thì scrypt có mạnh mấy cũng vô nghĩa — dò 6 ký tự vẫn nhanh. */
function kiemTraMatKhau(mk) {
  const s = String(mk ?? "");
  if (s.length < 8) throw new Error("Mật khẩu phải từ 8 ký tự trở lên.");
  if (s.trim().length === 0) throw new Error("Mật khẩu không được toàn dấu cách.");
}

/** Cắt một đoạn quanh chỗ khớp, thay vì gửi cả tin nhắn dài về giao diện.
 *
 *  Vị trí `vt` đo trên chuỗi ĐÃ BỎ DẤU. Với tiếng Việt gõ kiểu thường (NFC) thì mỗi chữ
 *  có dấu vẫn là một ký tự sau khi bỏ dấu, nên chỉ số dùng chung được. Nếu hai chuỗi lệch
 *  độ dài (văn bản ở dạng NFD) thì không dám cắt theo chỉ số nữa — lấy đoạn đầu cho chắc. */
function catQuanh(goc, chuan, vt, dai, truoc = 40, sau = 90) {
  if (chuan.length !== goc.length) return goc.length > 160 ? goc.slice(0, 160) + "…" : goc;
  const dau = Math.max(0, vt - truoc);
  const cuoi = Math.min(goc.length, vt + dai + sau);
  return (dau > 0 ? "…" : "") + goc.slice(dau, cuoi) + (cuoi < goc.length ? "…" : "");
}
