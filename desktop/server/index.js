// Khởi động máy chủ cục bộ của node: phục vụ web/ (UI + trang /join cho điện thoại),
// WebSocket /ui (giao diện cục bộ), WebSocket /peer (kết nối P2P), /file/*, /api/info.
// Chạy được TRONG Electron (main.js) hoặc ĐỘC LẬP bằng Node để thử nhanh:
//     node desktop/server/index.js --port 8000 --data ./data-a
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { WebSocketServer } from "ws";
import { Storage } from "./storage.js";
import { Node } from "./node.js";
import { localIp, localIps } from "./discovery.js";
import { ganNhan, hamNong } from "./mangcuc.js";
import { fingerprint } from "@sentinell/core";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Trang báo từ chối — phải nói rõ phải làm gì tiếp, kẻo người dùng tưởng app hỏng. */
function trangTuChoi(ly) {
  return `<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinell — chế độ web đang tắt</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;
background:#0b1020;color:#e6ecff;font-family:system-ui,"Segoe UI",Roboto,sans-serif}
div{max-width:380px;background:#111a2f;border:1px solid #223055;border-radius:16px;padding:22px}
h1{font-size:18px;margin:0 0 10px}p{color:#9fadcc;font-size:14px;line-height:1.6;margin:0 0 10px}
b{color:#e6ecff}</style>
<div><h1>🛡️ Chế độ web đang tắt cho mạng này</h1>
<p>${ly}</p>
<p>Sang máy tính, mở <b>🔑 Hiện khóa &amp; mã QR</b>, chọn đúng địa chỉ rồi quét lại mã.</p></div>`;
}

/** Yêu cầu này đến từ chính máy này (loopback) hay từ ngoài mạng?
 *  Chỉ tin loopback — không tin IP nào khác, kể cả IP LAN của chính máy: gói tin tới đó
 *  đã đi qua card mạng, tức là ai khác cũng gửi tới đó được. */
function laTrongMay(req) {
  const ip = (req.socket?.remoteAddress || "").replace(/^::ffff:/, "");
  return ip === "::1" || ip.startsWith("127.");
}

export async function startServer({ dataDir, port, webDir, protect = null }) {
  const storage = await Storage.open(dataDir, protect);
  const node = new Node({ storage, port });

  const app = express();

  // ------------------------------------------------------ khóa chế độ web theo card mạng
  //
  // Đây là lớp gia cố quan trọng nhất cho chế độ web. Mã JavaScript của /join đi qua HTTP,
  // nên ai đứng trên đường đều sửa được nó — và không có cách vá bằng mật mã (mã đã bị sửa
  // thì tự kiểm tra chính nó cũng vô nghĩa). Cách duy nhất còn lại: ĐỪNG PHỤC VỤ mã đó cho
  // mạng có người lạ.
  //
  // Áp cho TOÀN BỘ trang tĩnh và /api/info, không chỉ riêng /join: trang giao diện desktop
  // (`/`), các trang demo (`/demos/*`) và /api/info trước đây vẫn mở cho cả LAN — mà
  // /api/info còn khai ra danh sách đầy đủ các card mạng của máy, tức là lộ cả cấu trúc
  // mạng nội bộ cho bất kỳ ai cùng WiFi.
  app.use((req, res, next) => {
    const cho = node.choPhepWeb(req.socket?.remoteAddress);
    if (cho.duoc) { node.ghiTaiWeb(req.socket?.remoteAddress); return next(); }
    res.status(403).type("html").send(trangTuChoi(cho.ly));
  });

  app.get("/api/info", (_req, res) => {
    // Máy đang khóa: không khai tên, khóa công khai hay vân tay cho bất kỳ ai trong mạng.
    if (storage.locked) { res.json({ locked: true, port: node.port }); return; }
    // Đọc node.port (cổng THỰC SỰ đã bind) chứ không phải `port` yêu cầu ban đầu —
    // nếu cổng mặc định bận, app rơi sang cổng khác và mã QR mời phải mang cổng đúng.
    res.json({
      lan_ip: localIp(), port: node.port, pub: storage.idPub, name: storage.name,
      fp: fingerprint(storage.idPub),
      // Máy nhiều card mạng (VirtualBox/WSL/VPN) thì đoán có thể sai → gửi cả danh sách
      // để người dùng tự đổi địa chỉ trong mã QR nếu điện thoại không vào được.
      // Kèm nhãn an toàn cho từng card (nối trực tiếp / mạng riêng / mạng công cộng) —
      // người dùng phải thấy được mình đang chia sẻ qua đường nào.
      lan_ips: ganNhan(localIps()).map((d) => ({ ip: d.ip, iface: d.iface, muc: d.muc, nhan: d.nhan, an: d.an, y: d.y })),
    });
  });
  app.get("/file/:name", (req, res) => {
    // Cũng chỉ trong máy: đây là tệp đã nhận, và chỉ giao diện chạy ở 127.0.0.1 mới cần.
    // Trang /join dựng tệp bằng blob: ngay trong trình duyệt, không gọi đường này.
    if (!laTrongMay(req)) { res.status(403).json({ error: "chỉ truy cập được từ máy này" }); return; }
    const p = path.join(storage.filesDir, path.basename(req.params.name));
    res.sendFile(p, (err) => { if (err) res.status(404).json({ error: "not found" }); });
  });
  app.use(express.static(webDir, { extensions: ["html"] }));

  const server = http.createServer(app);
  // Giao diện gửi tệp qua đây bằng MỘT khung nhị phân (xem "send_file" bên dưới), nên
  // hạn kích thước phải đủ cho tệp lớn nhất mà giao diện cho phép chọn (200 MB).
  const wssUi = new WebSocketServer({ noServer: true, maxPayload: 220 * 1024 * 1024 });
  const wssPeer = new WebSocketServer({ noServer: true, maxPayload: 8 * 1024 * 1024 });

  server.on("upgrade", (req, socket, head) => {
    const { pathname } = new URL(req.url, "http://x");
    if (pathname === "/ui") {
      // CHỈ trong máy. `/ui` là kênh ĐIỀU KHIỂN: đọc được toàn bộ trạng thái và ra được
      // mọi lệnh (đọc lịch sử, gửi tin, xóa cuộc trò chuyện, xuất tệp tài khoản…). Máy chủ
      // bind 0.0.0.0 để điện thoại vào được /join, nên nếu không chặn ở đây thì bất kỳ ai
      // cùng mạng cũng chiếm được app — không cần phá mã hóa, không cần đứng giữa, chỉ cần
      // biết cổng. Giao diện thật luôn chạy ở 127.0.0.1 nên không có lý do gì mở ra ngoài.
      if (!laTrongMay(req)) { socket.destroy(); return; }
      wssUi.handleUpgrade(req, socket, head, (ws) => wssUi.emit("connection", ws, req));
    } else if (pathname === "/peer") {
      wssPeer.handleUpgrade(req, socket, head, (ws) => wssPeer.emit("connection", ws, req));
    } else socket.destroy();
  });

  wssUi.on("connection", (ws) => {
    node.uiClients.add(ws);
    ws.send(JSON.stringify(node.state()));
    ws.on("message", (data, isBinary) => {
      // Tệp đi bằng khung nhị phân:  u16BE(độ dài phần đầu) ‖ phần đầu JSON ‖ bytes thô.
      // Chặng này chỉ chạy trong máy (renderer ↔ node), nhưng vẫn đáng bỏ base64: một
      // tệp 10 MB từng phải hóa thành chuỗi 13 MB rồi JSON.parse — đủ để đứng hình giao diện.
      if (isBinary && data.length >= 2) {
        const nDau = data.readUInt16BE(0);
        let dau;
        try { dau = JSON.parse(data.subarray(2, 2 + nDau).toString("utf8")); } catch { return; }
        if (dau.cmd !== "send_file") return;
        node.sendFile(dau.name, dau.mime || "", data.subarray(2 + nDau))
          .catch((e) => node.uiBroadcast({ type: "notice", text: `Lỗi khi gửi tệp: ${e.message}`, bad: true }));
        return;
      }
      let cmd;
      try { cmd = JSON.parse(data.toString()); } catch { return; }
      node.handleUi(cmd).catch((e) => node.uiBroadcast({ type: "notice", text: `Lỗi: ${e.message}`, bad: true }));
    });
    ws.on("close", () => node.uiClients.delete(ws));
  });

  wssPeer.on("connection", (ws) => {
    // Chưa mở khóa thì không có khóa danh tính để bắt tay — từ chối tử tế, đừng để
    // bên kia ngồi chờ một cái handshake không bao giờ tới.
    if (storage.locked) {
      try { ws.send(JSON.stringify({ type: "rejected", reason: "Máy bên kia đang khóa — chủ máy chưa nhập mật khẩu." })); } catch { /* */ }
      ws.close();
      return;
    }
    // Phiên cũ có thể đã chết (đối phương rớt mạng/tắt app đột ngột). Nếu socket cũ
    // không còn mở thì dọn đi và nhận kết nối mới, thay vì kẹt "bận" vĩnh viễn.
    if (node.session && !node.isPeerAlive()) node.forceTeardown("Phiên cũ đã chết — nhận kết nối mới.");
    if (node.session) {
      ws.send(JSON.stringify({ type: "busy" }));
      ws.close();
      // Cho người dùng biết có thiết bị vừa bị chặn vì máy đang bận — nếu không thì
      // bên kia bị từ chối mà bên này chẳng hay biết gì, tưởng như không có chuyện gì.
      node.uiBroadcast({
        type: "notice",
        text: "📵 Một thiết bị vừa xin kết nối nhưng bị từ chối vì máy đang trò chuyện với "
          + `"${node.peerMeta?.name || "thiết bị khác"}". Ngắt kết nối hiện tại rồi bảo họ thử lại.`,
      });
      return;
    }
    node.attachPeer(ws, "R", null);
  });

  // Máy người dùng có thể đã dùng cổng mặc định (hoặc họ mở 2 bản một lúc) →
  // thử lần lượt vài cổng kế tiếp thay vì chết im lặng.
  // Đọc hồ sơ mạng của Windows ngay từ đầu (mất ~3,5s): tới lúc người dùng mở cửa sổ QR
  // thì kết quả đã nằm sẵn trong bộ đệm, không phải ngồi chờ.
  hamNong();

  const actualPort = await listenOnFreePort(server, port, 20);
  node.port = actualPort;      // discovery phải quảng bá đúng cổng đã bind
  // Đang khóa thì chưa quảng bá gì lên mạng cả — mDNS sẽ bật ngay sau khi mở khóa.
  if (!storage.locked) node.startDiscovery();

  return {
    node, server, port: actualPort,
    /** Tắt máy chủ cho BẰNG ĐƯỢC.
     *
     *  `server.close()` chỉ chờ mọi kết nối hiện có đóng lại — mà WebSocket `/ui` của
     *  giao diện thì không bao giờ tự đóng, nên nó treo mãi: `app.quit()` không tới lượt
     *  chạy, tiến trình Electron sống tiếp và GIỮ NGUYÊN cổng. Lần mở sau rơi sang cổng
     *  kế tiếp, còn cổng cũ vẫn có "xác" trả lời — mã QR cũ trỏ vào đó thì hoặc treo,
     *  hoặc (nếu bản cài đã bị ghi đè) trả về đúng một dòng "Cannot GET /join".
     *  Vì thế phải ngắt thẳng mọi socket, rồi vẫn đặt hạn giờ phòng khi có gì kẹt. */
    async stop() {
      try { await node.stop(); } catch { /* */ }
      for (const ws of node.uiClients) { try { ws.terminate(); } catch { /* */ } }
      node.uiClients.clear();
      try { node.peerWs?.terminate(); } catch { /* */ }
      try { wssUi.close(); wssPeer.close(); } catch { /* */ }
      try { server.closeAllConnections?.(); } catch { /* */ }
      await new Promise((resolve) => {
        const hanGio = setTimeout(resolve, 1500);
        server.close(() => { clearTimeout(hanGio); resolve(); });
      });
    },
  };
}

/** Bind cổng đầu tiên còn trống trong dải [startPort, startPort+tries). */
async function listenOnFreePort(server, startPort, tries) {
  for (let p = startPort; p < startPort + tries; p++) {
    try {
      await new Promise((resolve, reject) => {
        const onError = (e) => { server.removeListener("listening", onListening); reject(e); };
        const onListening = () => { server.removeListener("error", onError); resolve(); };
        server.once("error", onError);
        server.once("listening", onListening);
        server.listen(p, "0.0.0.0");
      });
      return p;
    } catch (e) {
      if (e.code !== "EADDRINUSE") throw e;
      // cổng bận → thử cổng kế tiếp
    }
  }
  throw new Error(`Không tìm được cổng trống trong dải ${startPort}–${startPort + tries - 1}.`);
}

// ---- chạy độc lập bằng Node (không Electron) ----
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const get = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
  const port = Number(get("--port", process.env.SENTINELL_PORT || 8000));
  const dataDir = path.resolve(get("--data", process.env.SENTINELL_DATA || "./data"));
  const webDir = path.resolve(__dirname, "../../web");
  startServer({ dataDir, port, webDir }).then(({ node, port: bound }) => {
    const ip = localIp();
    if (bound !== port) console.log(`(cổng ${port} đang bận → dùng cổng ${bound})`);
    console.log(`Sentinell node (Node.js) — UI: http://127.0.0.1:${bound}/  LAN: ${ip}:${bound}`);
    if (node.storage.locked) console.log("Máy đang KHÓA — mở trang trên rồi nhập mật khẩu.");
    else console.log(`Tên: ${node.storage.name}  Vân tay: ${fingerprint(node.storage.idPub)}`);
  }).catch((e) => { console.error(e); process.exit(1); });
}
