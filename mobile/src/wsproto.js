// Máy chủ WebSocket tối giản theo RFC 6455, chạy trên một socket TCP thô.
//
// Vì sao phải tự viết: React Native có sẵn WebSocket để GỌI đi, nhưng không có cách nào để
// NGHE. `react-native-tcp-socket` chỉ cho TCP trần, nên phần bắt tay HTTP Upgrade và khung
// WebSocket phải làm ở đây. Node desktop gọi sang bằng thư viện `ws` như gọi một máy tính khác,
// nên phía điện thoại phải nói ĐÚNG giao thức — không được "gần đúng".
//
// Tệp này KHÔNG phụ thuộc React Native: nó chỉ cần một socket có on('data'|'close'|'error'),
// write(bytes), end(), destroy(). Nhờ vậy scripts/test-wsserver.mjs kiểm được nó bằng socket
// của Node và chính thư viện `ws` của desktop.
//
// Những gì CỐ Ý không làm: nén permessage-deflate (không bắt tay mở rộng nào cả — client sẽ
// gửi khung không nén), subprotocol, TLS. Nội dung vốn đã được mã hóa đầu cuối ở tầng trên.
import { sha1 } from "@noble/hashes/legacy.js";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const te = new TextEncoder();

/** Khớp maxPayload của /peer bên desktop. Khối tệp là 256 KB nên 8 MB là dư. */
export const MAX_MESSAGE = 8 * 1024 * 1024;
const MAX_HEADER = 16 * 1024;

export const CONNECTING = 0, OPEN = 1, CLOSING = 2, CLOSED = 3;

function b64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

/** Sec-WebSocket-Accept = base64(SHA-1(key + GUID)) — RFC 6455 mục 4.2.2. */
export function acceptKey(key) {
  return b64(sha1(te.encode(key + GUID)));
}

function concat(a, b) {
  if (!a || a.length === 0) return b;
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function indexOfCrlf2(u8) {
  for (let i = 3; i < u8.length; i++) {
    if (u8[i] === 10 && u8[i - 1] === 13 && u8[i - 2] === 10 && u8[i - 3] === 13) return i + 1;
  }
  return -1;
}

/** Một kết nối WebSocket phía máy chủ, có API gần giống WebSocket của trình duyệt. */
export class WsConn {
  constructor(socket, { path = "/peer", maxMessage = MAX_MESSAGE, heartbeatMs = 15000, deadMs = 45000, refusal = null } = {}) {
    this.socket = socket;
    this.path = path;
    this.maxMessage = maxMessage;
    this.refusal = refusal;          // nội dung trả cho ai mở cổng này bằng trình duyệt
    this.remoteAddress = String(socket.remoteAddress || "").replace(/^::ffff:/, "");
    this.readyState = CONNECTING;
    this.onopen = null; this.onmessage = null; this.onclose = null; this.onerror = null;

    this._buf = new Uint8Array(0);
    this._frag = null;               // { opcode, parts[], size } khi tin nhắn bị chia nhiều khung
    this._closeSent = false;
    this._lastPong = Date.now();
    this._hbMs = heartbeatMs;
    this._deadMs = deadMs;
    this._hb = null;
    this._td = new TextDecoder("utf-8", { fatal: true });

    socket.on("data", (d) => this._onData(d instanceof Uint8Array ? d : te.encode(String(d))));
    socket.on("error", (e) => { try { this.onerror?.(e); } catch { /* */ } });
    socket.on("close", () => this._finish(this._closeCode ?? 1006, this._closeReason ?? ""));
  }

  // ------------------------------------------------------------------ nhận
  _onData(chunk) {
    this._buf = concat(this._buf, chunk);
    if (this.readyState === CONNECTING) {
      if (!this._handshake()) return;
    }
    while (this.readyState === OPEN || this.readyState === CLOSING) {
      if (!this._frame()) break;
    }
  }

  _handshake() {
    const end = indexOfCrlf2(this._buf);
    if (end < 0) {
      if (this._buf.length > MAX_HEADER) this._http(431, "Request Header Fields Too Large");
      return false;
    }
    const head = new TextDecoder().decode(this._buf.subarray(0, end));
    this._buf = this._buf.slice(end);
    const [line, ...rest] = head.split("\r\n");
    const [method, target] = line.split(" ");
    const h = {};
    for (const r of rest) {
      const i = r.indexOf(":");
      if (i > 0) h[r.slice(0, i).trim().toLowerCase()] = r.slice(i + 1).trim();
    }
    const path = (target || "").split("?")[0];
    const upgrade = /websocket/i.test(h.upgrade || "") && /upgrade/i.test(h.connection || "");
    if (method !== "GET" || path !== this.path || !upgrade) {
      this._http(upgrade ? 404 : 426, upgrade ? "Not Found" : "Upgrade Required", this.refusal);
      return false;
    }
    const key = h["sec-websocket-key"] || "";
    if (h["sec-websocket-version"] !== "13" || !/^[A-Za-z0-9+/]{22}==$/.test(key)) {
      this._http(400, "Bad Request");
      return false;
    }
    this.socket.write(te.encode(
      "HTTP/1.1 101 Switching Protocols\r\n"
      + "Upgrade: websocket\r\n"
      + "Connection: Upgrade\r\n"
      + `Sec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`));
    this.readyState = OPEN;
    this._startHeartbeat();
    try { this.onopen?.(); } catch (e) { this.onerror?.(e); }
    return true;
  }

  _http(code, text, body = null) {
    const b = te.encode(body || `${code} ${text}\n`);
    const head = te.encode(
      `HTTP/1.1 ${code} ${text}\r\nContent-Type: text/plain; charset=utf-8\r\n`
      + `Content-Length: ${b.length}\r\nConnection: close\r\n\r\n`);
    this.readyState = CLOSED;
    // end(data) = ghi XONG rồi mới đóng. Gọi write() rồi end() riêng là sai trên
    // react-native-tcp-socket: write chạy bất đồng bộ ở luồng native, end() đóng socket
    // ngay ⇒ phản hồi bị cắt, trình duyệt nhận "Empty reply" (đã gặp trên máy ảo).
    try { this.socket.end(concat(head, b)); } catch { /* */ }
  }

  /** Đóng chiều ghi SAU KHI mọi lần ghi trước đó đã ra khỏi máy (xem _http). */
  _endAfter() {
    try { this.socket.end(); } catch { /* */ }
  }

  /** Đọc MỘT khung nếu đủ byte. Trả false khi cần chờ thêm dữ liệu hoặc đã đóng. */
  _frame() {
    const u = this._buf;
    if (u.length < 2) return false;
    const fin = (u[0] & 0x80) !== 0;
    const rsv = u[0] & 0x70;
    const opcode = u[0] & 0x0f;
    const masked = (u[1] & 0x80) !== 0;
    let len = u[1] & 0x7f;
    let off = 2;
    // Không bắt tay mở rộng nào ⇒ mọi bit RSV phải là 0. Khung từ client BẮT BUỘC có mặt nạ.
    if (rsv) return this._fail(1002, "RSV khác 0");
    if (!masked) return this._fail(1002, "Khung từ client không có mặt nạ");
    if (len === 126) {
      if (u.length < 4) return false;
      len = (u[2] << 8) | u[3];
      off = 4;
    } else if (len === 127) {
      if (u.length < 10) return false;
      const hi = ((u[2] << 24) | (u[3] << 16) | (u[4] << 8) | u[5]) >>> 0;
      const lo = ((u[6] << 24) | (u[7] << 16) | (u[8] << 8) | u[9]) >>> 0;
      if (hi !== 0) return this._fail(1009, "Khung quá lớn");
      len = lo;
      off = 10;
    }
    // Kiểm độ dài TRƯỚC khi chờ đủ byte: đối phương khai 2 GB thì từ chối ngay, đừng gom bộ nhớ.
    if (len > this.maxMessage) return this._fail(1009, "Khung quá lớn");
    if (opcode >= 8 && (!fin || len > 125)) return this._fail(1002, "Khung điều khiển sai");
    if (u.length < off + 4 + len) return false;

    const mask = u.subarray(off, off + 4);
    const data = u.slice(off + 4, off + 4 + len);
    for (let i = 0; i < data.length; i++) data[i] ^= mask[i & 3];
    this._buf = u.subarray(off + 4 + len);

    switch (opcode) {
      case 0x0: {                                  // khung tiếp nối
        if (!this._frag) return this._fail(1002, "Khung tiếp nối lạc");
        this._frag.parts.push(data);
        this._frag.size += data.length;
        if (this._frag.size > this.maxMessage) return this._fail(1009, "Tin quá lớn");
        if (fin) {
          const { opcode: op, parts, size } = this._frag;
          this._frag = null;
          const all = new Uint8Array(size);
          let p = 0;
          for (const x of parts) { all.set(x, p); p += x.length; }
          return this._deliver(op, all);
        }
        return true;
      }
      case 0x1: case 0x2:                          // chữ / nhị phân
        if (this._frag) return this._fail(1002, "Tin mới chen giữa tin đang chia khung");
        if (!fin) { this._frag = { opcode, parts: [data], size: data.length }; return true; }
        return this._deliver(opcode, data);
      case 0x8: {                                  // đóng
        const code = data.length >= 2 ? (data[0] << 8) | data[1] : 1005;
        const reason = data.length > 2 ? new TextDecoder().decode(data.subarray(2)) : "";
        this._closeCode = code; this._closeReason = reason;
        this.readyState = CLOSING;
        if (!this._closeSent) this._sendClose(code === 1005 ? 1000 : code, "", () => this._endAfter());
        else this._endAfter();
        return false;
      }
      case 0x9: this._write(0xA, data); return true;           // ping → pong cùng nội dung
      case 0xA: this._lastPong = Date.now(); return true;      // pong
      default: return this._fail(1002, "Opcode không hỗ trợ");
    }
  }

  _deliver(opcode, bytes) {
    let data = bytes;
    if (opcode === 0x1) {
      try { data = this._td.decode(bytes); } catch { return this._fail(1007, "Chuỗi không phải UTF-8"); }
    }
    try { this.onmessage?.({ data }); } catch (e) { this.onerror?.(e); }
    return this.readyState === OPEN;
  }

  _fail(code, reason) {
    this._closeCode = code; this._closeReason = reason;
    this.readyState = CLOSING;
    if (!this._closeSent) this._sendClose(code, reason, () => this._endAfter());
    else this._endAfter();
    setTimeout(() => { try { this.socket.destroy(); } catch { /* */ } }, 1000);
    return false;
  }

  // ------------------------------------------------------------------ gửi
  _write(opcode, payload, cb) {
    const n = payload.length;
    const head = n < 126 ? 2 : n < 65536 ? 4 : 10;
    const out = new Uint8Array(head + n);
    out[0] = 0x80 | opcode;                          // khung từ máy chủ KHÔNG đeo mặt nạ
    if (n < 126) out[1] = n;
    else if (n < 65536) { out[1] = 126; out[2] = n >>> 8; out[3] = n & 0xff; }
    else {
      out[1] = 127;
      out[6] = (n >>> 24) & 0xff; out[7] = (n >>> 16) & 0xff; out[8] = (n >>> 8) & 0xff; out[9] = n & 0xff;
    }
    out.set(payload, head);
    try { this.socket.write(out, undefined, cb); } catch (e) { this.onerror?.(e); }
  }

  send(data) {
    if (this.readyState !== OPEN) return;
    if (typeof data === "string") this._write(0x1, te.encode(data));
    else this._write(0x2, data instanceof Uint8Array ? data : new Uint8Array(data));
  }

  ping() { if (this.readyState === OPEN) this._write(0x9, new Uint8Array(0)); }

  _sendClose(code, reason, then) {
    this._closeSent = true;
    const r = te.encode(reason || "").subarray(0, 123);
    const p = new Uint8Array(2 + r.length);
    p[0] = code >>> 8; p[1] = code & 0xff; p.set(r, 2);
    this._write(0x8, p, then);
  }

  close(code = 1000, reason = "") {
    if (this.readyState === CLOSED || this.readyState === CLOSING) return;
    const dangMo = this.readyState === OPEN;
    this.readyState = CLOSING;
    this._closeCode = this._closeCode ?? code;
    // Tin cuối (vd. {type:"busy"}) và khung đóng phải ra khỏi máy TRƯỚC khi đóng socket.
    if (dangMo && !this._closeSent) this._sendClose(code, reason, () => this._endAfter());
    else this._endAfter();
    setTimeout(() => { try { this.socket.destroy(); } catch { /* */ } }, 1000);
  }

  // Nhịp tim: đối phương rớt mạng/tắt máy đột ngột thì socket không tự đóng — không có
  // cái này thì điện thoại kẹt "đang bận" mãi (đúng lỗi desktop từng gặp).
  _startHeartbeat() {
    if (!this._hbMs) return;
    this._hb = setInterval(() => {
      if (this.readyState !== OPEN) { clearInterval(this._hb); return; }
      if (Date.now() - this._lastPong > this._deadMs) {
        // Peer đã chết thì chào tạm biệt cũng chẳng ai nghe — hủy socket ngay để onclose
        // bắn liền và điện thoại hết "bận", thay vì chờ thêm 1 giây hẹn giờ của _fail().
        this._closeCode = 1001; this._closeReason = "Đối phương không phản hồi";
        clearInterval(this._hb);
        try { this.socket.destroy(); } catch { /* */ }
        return;
      }
      this.ping();
    }, this._hbMs);
  }

  _finish(code, reason) {
    if (this.readyState === CLOSED && this._closedFired) return;
    this.readyState = CLOSED;
    clearInterval(this._hb);
    if (this._closedFired) return;
    this._closedFired = true;
    try { this.onclose?.({ code, reason }); } catch { /* */ }
  }
}
