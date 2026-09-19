// Một phiên nhắn tin với một thiết bị khác, chạy giao thức @sentinell/core NGAY TRÊN ĐIỆN
// THOẠI (đầu cuối thật). Dùng cho CẢ HAI chiều:
//   • connect(host, port) — điện thoại GỌI tới /peer của máy khác (vai "I", WebSocket có sẵn);
//   • accept(conn)        — máy khác gọi VÀO điện thoại (vai "R", máy chủ tự viết wsproto.js).
// Luồng tin giống hệt desktop/server/node.js, nên hai bên nào nói chuyện với nhau cũng được.
import { Session, sha256Hex, isBinaryFrame, loiMoTaTep, SO_TEP_NHAN_CUNG_LUC, fingerprint } from "@sentinell/core";

const CHUNK = 256 * 1024;   // khối lớn hơn = ít vòng mã hóa/JSON hơn → nhanh hơn nhiều trên điện thoại
const HAN_DUYET_MS = 60000;

export class PeerLink {
  constructor({
    identity, expectPub = null, pairCode = null, activePairCode = null, listenPort = null,
    lookupContact = null, strict = false,
    onLog, onConnected, onMessage, onDisconnected, onNotice, onProgress, onApproval,
  }) {
    this.identity = identity;
    this.expectPub = expectPub;
    this.pairCode = pairCode;              // mã tôi quét được từ QR của bên kia
    this.activePairCode = activePairCode;  // mã TÔI đang hiện trong QR của mình
    this.listenPort = listenPort;          // cổng tôi đang nghe → bên kia lưu để gọi lại được
    this.lookupContact = lookupContact;    // pub → liên hệ đã ghim (hoặc null)
    this.strict = strict;                  // chỉ nhận liên hệ đã ghim
    this.h = { onLog, onConnected, onMessage, onDisconnected, onNotice, onProgress, onApproval };
    this.ws = null;
    this.role = null;
    this.session = null;
    this.files = new Map();
    this.closedByUser = false;
    this.closed = false;
    this.peerAddr = null;                  // { host, port } để lưu vào danh bạ
    this.pending = null;                   // { msg, timer } khi đang chờ người dùng duyệt
    this._deferredSig = null;
  }

  /** Chủ động gọi sang máy khác. */
  connect(host, port) {
    this.peerAddr = { host, port };
    const ws = new WebSocket(`ws://${host}:${port}/peer`);
    ws.binaryType = "arraybuffer";   // khối tệp về dạng khung nhị phân, không phải Blob
    ws.onerror = () => { if (!this.session?.ready) this.h.onNotice?.(`Không kết nối được ${host}:${port}`, true); };
    this._attach(ws, "I");
  }

  /** Máy khác vừa gọi vào (bắt tay WebSocket đã xong). */
  accept(conn) {
    this.peerAddr = { host: conn.remoteAddress || null, port: null };
    this._attach(conn, "R");
    // Kết nối vào đã mở sẵn nên không có sự kiện onopen — tự gửi hello luôn.
    conn.send(JSON.stringify(this.session.hello()));
  }

  _attach(ws, role) {
    this.ws = ws;
    this.role = role;
    this.session = new Session({
      role, idPriv: this.identity.priv, idPub: this.identity.pub,
      name: this.identity.name, onLog: (s, d) => this.h.onLog?.(s, d),
      pairCode: this.pairCode,
      activePairCode: this.activePairCode,
      listenPort: this.listenPort,
    });
    if (role === "I") ws.onopen = () => ws.send(JSON.stringify(this.session.hello()));
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        let m;
        try { m = JSON.parse(ev.data); } catch { return; }
        this._onMsg(m).catch((e) => this.h.onNotice?.(`Lỗi khi xử lý dữ liệu từ thiết bị kia: ${e?.message || e}`, true));
        return;
      }
      this._onBinary(ev.data instanceof Uint8Array ? ev.data : new Uint8Array(ev.data));
    };
    ws.onclose = () => {
      if (this.closed) return;
      this.closed = true;
      if (this.pending) { clearTimeout(this.pending.timer); this.pending = null; this.h.onApproval?.(null); }
      this.h.onDisconnected?.(this.closedByUser ? "Bạn đã rời phòng." : "Kết nối đã đóng.", this.session?.ready);
    };
  }

  get ready() { return !!(this.session && this.session.ready); }
  get busy() { return !this.closed; }

  async _onMsg(msg) {
    const s = this.session;
    if (!s) return;
    switch (msg.type) {
      case "busy":
        this.h.onNotice?.("Thiết bị kia đang bận (đã có phiên khác).", true);
        break;
      case "rejected":
        this.h.onNotice?.("Thiết bị kia từ chối kết nối. " + (msg.reason || ""), true);
        break;
      case "pending":
        // Bên kia đang hỏi chủ nhân của họ — báo rõ để đừng tưởng là treo máy.
        this.h.onNotice?.("⏳ Hãy sang thiết bị kia bấm \"Chấp nhận\" để vào chat.");
        break;
      case "hs": {
        if (this.peerAddr && !this.peerAddr.port && msg.listen_port) this.peerAddr.port = msg.listen_port;
        // KIỂM SOÁT KẾT NỐI ĐẾN (chỉ phía nhận): khóa lạ phải được người dùng duyệt,
        // hoặc bị từ chối thẳng nếu bật chế độ chặt. Y như desktop.
        if (this.role === "R") {
          const known = this.lookupContact ? await this.lookupContact(msg.id_pub) : null;
          if (!known) {
            if (this.strict) { this.reject(msg, "Thiết bị này chỉ nhận kết nối từ liên hệ đã ghim khóa."); return; }
            this._askApproval(msg);
            return;
          }
        }
        this.ws.send(JSON.stringify(s.onHello(msg)));
        if (this.role === "I") this.h.onNotice?.("Đang chờ thiết bị kia chấp nhận kết nối…");
        break;
      }
      case "hs-sig": {
        // Chữ ký có thể tới TRƯỚC khi người dùng kịp bấm duyệt (lúc đó chưa gọi onHello
        // nên session.peer còn rỗng) → giữ lại, xử lý sau khi duyệt.
        if (this.pending || !s.peer) { this._deferredSig = msg; return; }
        let pinned = this.expectPub;
        if (pinned == null && this.lookupContact) {
          const c = await this.lookupContact(s.peer.id_pub);
          pinned = c ? c.pub : null;
        }
        s.onSig(msg, pinned);
        if (s.authFailed) {
          this.h.onNotice?.("❌ Xác thực thất bại — khóa không khớp khóa đã ghim. Có thể bị mạo danh!", true);
          this.ws.close();
          return;
        }
        this.h.onConnected?.({
          peerName: s.peer.name, peerPub: s.peer.id_pub, trusted: s.trusted, safety: s.safety,
          peerProvedPair: s.peerProvedPair, role: this.role,
          host: this.peerAddr?.host || null, port: this.peerAddr?.port || null,
        });
        break;
      }
      case "msg": {
        let obj;
        try { obj = s.decrypt(msg); }
        catch { this.h.onNotice?.("Tin đến không giải mã được (toàn vẹn hỏng).", true); return; }
        this._onPlain(obj);
        break;
      }
    }
  }

  /** Khung nhị phân = một khối tệp (xem khuôn khung ở core/protocol.js). */
  _onBinary(u8) {
    const s = this.session;
    if (!s?.ready || !isBinaryFrame(u8)) return;
    let r;
    try { r = s.decryptBinary(u8, true); }
    catch { this.h.onNotice?.("Một khối tệp đến bị hỏng hoặc đã bị sửa — đã bỏ qua để an toàn.", true); return; }
    if (r.mtype !== "file-chunk") return;
    if (r.meta.idx === 0) this.h.onLog?.("decrypt", `Nhận khối tệp đầu tiên: AES-256-GCM + kiểm toàn vẹn OK (seq=${r.seq}).`);
    this._nhanKhoi(r.meta.name, r.meta.idx, r.bytes.slice());
  }

  _onPlain(obj) {
    if (obj.type === "text") { this.h.onMessage?.(obj); return; }
    if (obj.type === "file-meta") {
      // Kiểm TRƯỚC khi cấp phát: mọi con số ở đây là do máy bên kia nói.
      const loi = loiMoTaTep(obj);
      if (loi) { this.h.onNotice?.(`Mô tả tệp không hợp lệ (${loi}) — đã bỏ qua.`, true); return; }
      if (this.files.size >= SO_TEP_NHAN_CUNG_LUC) { this.h.onNotice?.("Quá nhiều tệp cùng lúc — đã bỏ qua bớt.", true); return; }
      this.files.set(obj.name, { meta: obj, chunks: new Array(obj.chunks).fill(null), recv: 0 });
      this.h.onProgress?.({ dir: "in", name: obj.name, done: 0, total: obj.chunks });
      return;
    }
    // Đường JSON+base64 — chỉ còn dùng khi đối phương chưa hiểu khung nhị phân.
    if (obj.type === "file-chunk") this._nhanKhoi(obj.name, obj.idx, b64ToBytes(obj.data));
  }

  /** Gộp một khối vào tệp đang nhận dở (dùng chung cho cả hai đường truyền). */
  _nhanKhoi(name, idx, bytes) {
    const ent = this.files.get(name);
    if (!ent || ent.chunks[idx] !== null) return;
    ent.chunks[idx] = bytes;
    ent.recv++;
    this.h.onProgress?.({ dir: "in", name, done: ent.recv, total: ent.meta.chunks });
    if (ent.recv !== ent.meta.chunks) return;

    const total = ent.chunks.reduce((n, c) => n + c.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of ent.chunks) { out.set(c, off); off += c.length; }
    const ok = sha256Hex(out) === ent.meta.hash;
    const mime = ent.meta.mime || "application/octet-stream";
    this.h.onMessage?.({
      type: "file", name: ent.meta.name, mime, size: total, integrity: ok,
      // Ảnh phải quay lại base64 để <Image> của React Native hiển thị được — nhưng
      // chỉ MỘT lần cho cả tệp, không phải mỗi khối như đường truyền cũ.
      dataUri: `data:${mime};base64,${bytesToB64(out)}`,
    });
    this.files.delete(name);
  }

  sendText(text) {
    const t = String(text || "").trim();
    if (!t || !this.ready) return null;
    this.ws.send(JSON.stringify(this.session.encrypt("text", { text: t })));
    return { type: "text", text: t };
  }

  /** Gửi ảnh/tệp: giải base64 MỘT lần thành bytes, rồi chia khối và gửi thẳng bytes.
   *  Trước đây mỗi khối còn phải base64 lại (+33%) và bản mã in ra hex (+100%) — riêng
   *  việc dựng chuỗi đó đã ngốn hơn cả AES, và trên Hermes thì thấy rõ là giật. */
  sendFile({ base64, name, mime }) {
    if (!this.ready) return null;
    const bytes = b64ToBytes(base64);
    const chunks = Math.max(1, Math.ceil(bytes.length / CHUNK));
    const hash = sha256Hex(bytes);
    const nhiPhan = this.session.peerBinary;
    this.ws.send(JSON.stringify(this.session.encrypt("file-meta", { name, size: bytes.length, mime, hash, chunks })));
    this.h.onProgress?.({ dir: "out", name, done: 0, total: chunks });
    for (let i = 0; i < chunks; i++) {
      const slice = bytes.subarray(i * CHUNK, (i + 1) * CHUNK);
      if (nhiPhan) this.ws.send(this.session.encryptBinary("file-chunk", { name, idx: i }, slice, i !== 0));
      else this.ws.send(JSON.stringify(this.session.encrypt("file-chunk", { name, idx: i, data: bytesToB64(slice) })));
      this.h.onProgress?.({ dir: "out", name, done: i + 1, total: chunks });
    }
    return { type: "file", name, mime, size: bytes.length, integrity: true, dataUri: `data:${mime};base64,${base64}` };
  }

  // ------------------------------------------------------------------ duyệt kết nối đến
  _askApproval(msg) {
    this.pending = {
      msg,
      timer: setTimeout(() => this.reject(msg, "Không có phản hồi (hết thời gian chờ)."), HAN_DUYET_MS),
    };
    // Nói cho bên gọi biết vì sao phải chờ — nếu không họ chỉ thấy "đang kết nối" đứng im.
    try { this.ws.send(JSON.stringify({ type: "pending", reason: "họ đang được hỏi có chấp nhận kết nối này không." })); } catch { /* */ }
    this.h.onApproval?.({ name: msg.name || "?", fp: fingerprint(msg.id_pub), pub: msg.id_pub, host: this.peerAddr?.host || null });
  }

  /** Người dùng bấm "Chấp nhận" → tiếp tục bắt tay như bình thường. */
  approve() {
    const p = this.pending;
    if (!p || this.closed) return;
    clearTimeout(p.timer);
    this.pending = null;
    this.h.onApproval?.(null);
    this.ws.send(JSON.stringify(this.session.onHello(p.msg)));
    const d = this._deferredSig;
    this._deferredSig = null;
    if (d) this._onMsg(d).catch(() => {});
  }

  /** Từ chối: báo cho bên kia biết lý do rồi đóng, thay vì im lặng bỏ mặc. */
  reject(msg, reason) {
    if (this.pending) { clearTimeout(this.pending.timer); this.pending = null; }
    this.h.onApproval?.(null);
    try { this.ws?.send(JSON.stringify({ type: "rejected", reason })); } catch { /* */ }
    this.h.onNotice?.(`Đã từ chối kết nối từ "${msg?.name || "thiết bị lạ"}". ${reason}`);
    this.closedByUser = true;
    try { this.ws?.close(); } catch { /* */ }
  }

  close() {
    this.closedByUser = true;
    try { this.ws?.close(); } catch { /* */ }
  }
}

/** Đang có phiên khác → báo "bận" cho người mới gọi vào rồi đóng. */
export function tuChoiBan(conn) {
  try { conn.send(JSON.stringify({ type: "busy" })); } catch { /* */ }
  try { conn.close(); } catch { /* */ }
}

// ---- base64 <-> bytes (Hermes có atob/btoa) ----
export function b64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
export function bytesToB64(bytes) {
  let s = "";
  const STEP = 0x8000;
  for (let i = 0; i < bytes.length; i += STEP) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + STEP));
  }
  return btoa(s);
}
