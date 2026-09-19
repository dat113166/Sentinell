// Kiểm máy chủ WebSocket tự viết của điện thoại (mobile/src/wsproto.js) bằng socket TCP thật
// của Node và CHÍNH thư viện `ws` mà node desktop dùng để gọi sang. Nếu `ws` bắt tay và nhắn
// được với nó ở đây thì desktop gọi sang điện thoại cũng được — đó là mục đích của bài này.
import net from "node:net";
import crypto from "node:crypto";
import WebSocket from "ws";
import { Session, genKeypair, isBinaryFrame } from "@sentinell/core";
import { WsConn, acceptKey } from "../mobile/src/wsproto.js";

let loi = 0;
const dat = (ten, ok, them = "") => {
  console.log(`${ten.padEnd(58, " ")} ${ok ? "OK" : "SAI"}${them ? "  " + them : ""}`);
  if (!ok) loi++;
};
const cho = (ms) => new Promise((r) => setTimeout(r, ms));

/** Dựng một máy chủ TCP, bọc mỗi socket bằng WsConn. */
function mayChu(opts = {}, onConn = () => {}) {
  const conns = [];
  const srv = net.createServer((sock) => {
    const c = new WsConn(sock, opts);
    conns.push(c);
    onConn(c);
  });
  return new Promise((res) => srv.listen(0, "127.0.0.1", () => res({ srv, port: srv.address().port, conns })));
}

function moWs(port, path = "/peer") {
  return new Promise((res, rej) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}${path}`);
    ws.once("open", () => res(ws));
    ws.once("error", rej);
  });
}

// ------------------------------------------------------------------ 1. vector chuẩn RFC 6455 mục 1.3
dat("khóa Accept đúng ví dụ RFC 6455", acceptKey("dGhlIHNhbXBsZSBub25jZQ==") === "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

// ------------------------------------------------------------------ 2–5. dội lại qua client `ws`
{
  const { srv, port } = await mayChu({ heartbeatMs: 0 }, (c) => {
    c.onmessage = ({ data }) => c.send(data);   // dội nguyên văn
  });
  const ws = await moWs(port);
  dat("thư viện ws bắt tay được với máy chủ tự viết", ws.readyState === WebSocket.OPEN);

  const nhan = () => new Promise((r) => ws.once("message", (d, isBin) => r({ d, isBin })));

  const chu = "Xin chào — tiếng Việt có dấu ✓ «ổn định»";
  ws.send(chu);
  let r = await nhan();
  dat("tin chữ UTF-8 dội về nguyên vẹn", !r.isBin && r.d.toString() === chu);

  const lon = crypto.randomBytes(300 * 1024);   // > 65535 ⇒ dùng độ dài 64-bit
  ws.send(lon);
  r = await nhan();
  dat("tin nhị phân 300 KB (độ dài 64-bit) nguyên vẹn", r.isBin && Buffer.compare(r.d, lon) === 0);

  const vua = crypto.randomBytes(1000);          // 126..65535 ⇒ độ dài 16-bit
  ws.send(vua);
  r = await nhan();
  dat("tin nhị phân 1000 B (độ dài 16-bit) nguyên vẹn", r.isBin && Buffer.compare(r.d, vua) === 0);

  ws.send("phần 1 ", { fin: false });
  ws.send("phần 2 ", { fin: false });
  ws.send("phần cuối", { fin: true });
  r = await nhan();
  dat("tin chia 3 khung được ghép lại đúng", r.d.toString() === "phần 1 phần 2 phần cuối");

  const pong = new Promise((res) => ws.once("pong", (d) => res(d.toString())));
  ws.ping("nhip");
  dat("ping của client được đáp pong cùng nội dung", (await pong) === "nhip");

  const dong = new Promise((res) => ws.once("close", (code) => res(code)));
  ws.close(1000, "tạm biệt");
  dat("đóng tử tế: client nhận mã 1000", (await dong) === 1000);
  srv.close();
}

// ------------------------------------------------------------------ 6. tin quá lớn → 1009
{
  let maServer = null;
  const { srv, port } = await mayChu({ heartbeatMs: 0, maxMessage: 64 * 1024 }, (c) => {
    c.onclose = ({ code }) => { maServer = code; };
  });
  const ws = await moWs(port);
  const dong = new Promise((res) => ws.once("close", (code) => res(code)));
  ws.send(crypto.randomBytes(200 * 1024));
  const code = await dong;
  dat("tin vượt giới hạn bị đóng với mã 1009", code === 1009, `client=${code}`);
  await cho(50);
  dat("máy chủ ghi nhận lý do 1009", maServer === 1009, `server=${maServer}`);
  srv.close();
}

// ------------------------------------------------------------------ 7. khai độ dài khổng lồ → từ chối NGAY
{
  const { srv, port } = await mayChu({ heartbeatMs: 0 });
  const s = net.connect(port, "127.0.0.1");
  await new Promise((r) => s.once("connect", r));
  const key = crypto.randomBytes(16).toString("base64");
  s.write(`GET /peer HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
  await cho(50);
  // Khai 2 GB nhưng chỉ gửi header: máy chủ phải đóng ngay, không chờ gom 2 GB.
  const head = Buffer.from([0x82, 0xff, 0, 0, 0, 0, 0x80, 0, 0, 0, 1, 2, 3, 4]);
  const buf = [];
  s.on("data", (d) => buf.push(d));
  const dong = new Promise((r) => s.once("close", r));
  s.write(head);
  await Promise.race([dong, cho(1500)]);
  const all = Buffer.concat(buf);
  const idx = all.indexOf(Buffer.from([0x88]));
  const code = idx >= 0 ? all.readUInt16BE(idx + 2) : null;
  dat("khai độ dài 2 GB ⇒ đóng ngay với 1009, không gom bộ nhớ", code === 1009, `code=${code}`);
  s.destroy();
  srv.close();
}

// ------------------------------------------------------------------ 8. khung không đeo mặt nạ → 1002
{
  const { srv, port } = await mayChu({ heartbeatMs: 0 });
  const s = net.connect(port, "127.0.0.1");
  await new Promise((r) => s.once("connect", r));
  const key = crypto.randomBytes(16).toString("base64");
  const buf = [];
  s.on("data", (d) => buf.push(d));
  s.write(`GET /peer HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
  await cho(50);
  const resp = Buffer.concat(buf).toString();
  dat("phản hồi 101 mang đúng Sec-WebSocket-Accept", resp.startsWith("HTTP/1.1 101") && resp.includes(acceptKey(key)));
  buf.length = 0;
  s.write(Buffer.from([0x81, 0x02, 0x68, 0x69]));   // "hi" KHÔNG mặt nạ
  await cho(100);
  const all = Buffer.concat(buf);
  const code = all[0] === 0x88 ? all.readUInt16BE(2) : null;
  dat("khung không mặt nạ bị đóng với 1002", code === 1002, `code=${code}`);
  s.destroy();
  srv.close();
}

// ------------------------------------------------------------------ 9. trình duyệt mở nhầm cổng
{
  const { srv, port } = await mayChu({ heartbeatMs: 0, refusal: "Đây là cổng nhắn tin của app Sentinell." });
  const r = await fetch(`http://127.0.0.1:${port}/`);
  const body = await r.text();
  dat("GET thường nhận 426 + lời giải thích, không treo", r.status === 426 && body.includes("Sentinell"), `status=${r.status}`);
  let loiMo = null;
  try { await moWs(port, "/khac"); } catch (e) { loiMo = e.message; }
  dat("WebSocket tới đường dẫn khác /peer bị từ chối (404)", !!loiMo && loiMo.includes("404"), loiMo || "");
  srv.close();
}

// ------------------------------------------------------------------ 10. nhịp tim phát hiện peer chết
{
  let ly = null;
  const { srv, port } = await mayChu({ heartbeatMs: 100, deadMs: 350 }, (c) => {
    c.onclose = ({ code }) => { ly = code; };
  });
  // Client `ws` tự đáp pong ⇒ phải còn sống sau nhiều nhịp.
  const ws = await moWs(port);
  await cho(600);
  dat("client còn đáp pong ⇒ không bị ngắt oan", ws.readyState === WebSocket.OPEN);
  ws.terminate();
  // Socket thô bắt tay xong rồi im lặng (không đáp ping) ⇒ phải bị ngắt.
  const s = net.connect(port, "127.0.0.1");
  await new Promise((r) => s.once("connect", r));
  const key = crypto.randomBytes(16).toString("base64");
  s.write(`GET /peer HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
  ly = null;
  await cho(800);
  dat("peer im lặng không đáp ping ⇒ bị ngắt (1001)", ly === 1001, `code=${ly}`);
  s.destroy();
  srv.close();
}

// ------------------------------------------------------------------ 11. một phiên Sentinell THẬT
// Desktop gọi (vai I, qua `ws`) → điện thoại nghe (vai R, qua WsConn). Chạy đúng luồng tin như
// node.js/transport.js: hai bên gửi hs, hai bên đáp hs-sig, rồi chữ + khung nhị phân hai chiều.
{
  const pc = genKeypair(), dt = genKeypair();
  const nhanDT = [];
  let R = null;
  const { srv, port } = await mayChu({ heartbeatMs: 0 }, (c) => {
    R = new Session({ role: "R", idPriv: dt.priv, idPub: dt.pub, name: "Điện thoại" });
    c.onopen = () => c.send(JSON.stringify(R.hello()));
    c.onmessage = ({ data }) => {
      if (typeof data !== "string") {
        const r = R.decryptBinary(data, true);
        nhanDT.push({ bin: r.bytes.length, meta: r.meta });
        c.send(R.encryptBinary("file-chunk", { name: "tra-lai.bin", idx: 0 }, r.bytes, true));
        return;
      }
      const m = JSON.parse(data);
      if (m.type === "hs") c.send(JSON.stringify(R.onHello(m)));
      else if (m.type === "hs-sig") R.onSig(m, null);
      else if (m.type === "msg") {
        const o = R.decrypt(m);
        nhanDT.push(o);
        c.send(JSON.stringify(R.encrypt("text", { text: `ĐT đã nhận: ${o.text}` })));
      }
    };
  });

  const I = new Session({ role: "I", idPriv: pc.priv, idPub: pc.pub, name: "PC" });
  const ws = new WebSocket(`ws://127.0.0.1:${port}/peer`, { maxPayload: 8 * 1024 * 1024 });
  const tinPC = [];
  let sanSang;
  const daSan = new Promise((r) => { sanSang = r; });
  ws.on("open", () => ws.send(JSON.stringify(I.hello())));
  ws.on("message", (d, isBin) => {
    if (isBin || isBinaryFrame(d)) { tinPC.push(I.decryptBinary(d, true)); return; }
    const m = JSON.parse(d.toString());
    if (m.type === "hs") ws.send(JSON.stringify(I.onHello(m)));
    else if (m.type === "hs-sig") { I.onSig(m, dt.pub); sanSang(); }   // PC đã ghim khóa điện thoại
    else if (m.type === "msg") tinPC.push(I.decrypt(m));
  });
  await Promise.race([daSan, cho(3000)]);
  await cho(100);
  dat("bắt tay Sentinell qua máy chủ tự viết: hai bên sẵn sàng", I.ready && R?.ready);
  dat("PC ghim đúng khóa điện thoại ⇒ tin cậy", I.trusted === true);
  dat("safety number hai bên khớp", I.safety === R.safety && I.safety.length > 0);

  ws.send(JSON.stringify(I.encrypt("text", { text: "chào điện thoại" })));
  const goc = crypto.randomBytes(256 * 1024);
  ws.send(I.encryptBinary("file-chunk", { name: "anh.jpg", idx: 0 }, goc, true));
  await cho(300);
  dat("điện thoại giải mã tin chữ của PC", nhanDT[0]?.text === "chào điện thoại");
  dat("điện thoại giải mã khối tệp 256 KB của PC", nhanDT[1]?.bin === goc.length && nhanDT[1]?.meta?.name === "anh.jpg");
  dat("PC giải mã tin trả lời của điện thoại", tinPC.some((t) => t.text === "ĐT đã nhận: chào điện thoại"));
  const traLai = tinPC.find((t) => t.mtype === "file-chunk");
  dat("PC nhận lại khối tệp, nguyên vẹn từng byte", !!traLai && Buffer.compare(Buffer.from(traLai.bytes), goc) === 0);
  ws.close();
  srv.close();
}

// ------------------------------------------------------------------ 12. socket kiểu React Native
// react-native-tcp-socket: write() chạy BẤT ĐỒNG BỘ ở luồng native, end() đóng socket NGAY.
// Socket Node ghi theo thứ tự nên không lộ lỗi này; trên máy ảo thì trình duyệt nhận "Empty
// reply" và tin {type:"busy"} biến mất. Giả lập đúng hành vi đó để lỗi không quay lại.
{
  function kieuRN(sock) {
    return {
      remoteAddress: sock.remoteAddress,
      on: (e, f) => sock.on(e, f),
      write(data, _enc, cb) { setTimeout(() => { if (!sock.destroyed && sock.writable) sock.write(data, cb); }, 15); return true; },
      end(data) { if (data) this.write(data, undefined, () => sock.end()); else sock.end(); },
      destroy() { sock.destroy(); },
    };
  }
  const srv = net.createServer((sock) => {
    const c = new WsConn(kieuRN(sock), { heartbeatMs: 0, refusal: "Cổng nhắn tin của app Sentinell." });
    c.onopen = () => { c.send(JSON.stringify({ type: "busy" })); c.close(); };   // y như tuChoiBan()
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  let body = null;
  try { body = await (await fetch(`http://127.0.0.1:${port}/`)).text(); } catch (e) { body = "LỖI " + e.message; }
  dat("[kiểu RN] trình duyệt vẫn nhận đủ lời giải thích", body.includes("Sentinell"), body.slice(0, 40));
  const ws = new WebSocket(`ws://127.0.0.1:${port}/peer`);
  const tin = await new Promise((r) => { ws.on("message", (d) => r(String(d))); ws.on("close", () => r(null)); ws.on("error", () => r(null)); });
  dat("[kiểu RN] tin 'busy' ra khỏi máy trước khi socket đóng", tin === '{"type":"busy"}', String(tin));
  srv.close();
}

console.log(loi ? `\n${loi} mục SAI` : "\nTất cả đều đạt.");
process.exit(loi ? 1 : 0);
