// Node Sentinell (Node.js) — port từ reference/python/sentinell/node.py.
// Giữ NGUYÊN giao diện sự kiện với giao diện web (web/js/ui.js) và khuôn gói tin /peer,
// nên UI hiện có dùng lại không đổi, và node Python vẫn là peer hợp lệ.
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import WebSocket from "ws";
import { Session, fingerprint, newPairCode, isBinaryFrame, loiMoTaTep, SO_TEP_NHAN_CUNG_LUC } from "@sentinell/core";
import { Discovery, localIps } from "./discovery.js";
import { cungMangCon, ganNhan, hamNong, raMang, quenNenArp } from "./mangcuc.js";

const CHUNK = 256 * 1024;

/** Mã lỗi mạng của Node (ECONNREFUSED, EHOSTUNREACH…) chẳng nói gì với người dùng cuối.
 *  Dịch sang câu nói rõ nên làm gì tiếp theo. */
function dichLoiMang(e) {
  const ma = e?.code || "";
  const bang = {
    ECONNREFUSED: "thiết bị đó không mở Sentinell, hoặc đang dùng cổng khác.",
    EHOSTUNREACH: "không tới được máy đó — kiểm tra hai bên có cùng WiFi/hotspot không.",
    ENETUNREACH: "mạng hiện không dùng được.",
    ETIMEDOUT: "quá hạn chờ — có thể tường lửa đang chặn, hoặc địa chỉ đã cũ.",
    ENOTFOUND: "không tìm thấy địa chỉ này.",
    ECONNRESET: "thiết bị kia đã ngắt giữa chừng.",
  };
  return bang[ma] || (e?.message || "lỗi không rõ") + ".";
}

export class Node {
  /** Chế độ web chỉ mở bấy nhiêu lâu sau mỗi lần mở cửa sổ QR. */
  static WEB_MO_MS = 30 * 60 * 1000;

  constructor({ storage, port }) {
    this.storage = storage;
    this.port = port;
    this.nodeId = crypto.randomBytes(6).toString("hex");
    this.uiClients = new Set();
    this.discovery = null;
    this.peers = [];
    this.session = null;
    this.peerWs = null;
    this.peerMeta = {};
    this.expectPub = null;
    this._incoming = new Map();
    this.pairCode = newPairCode();   // mã ghép đôi đang hiện (nhúng vào QR)
    this.scannedPairCode = null;     // mã tôi vừa QUÉT được của thiết bị khác
    this.pendingApproval = null;     // {msg, timer} — kết nối đến đang chờ người dùng duyệt
    this.peerAddr = null;            // địa chỉ peer của phiên hiện tại, để lưu danh bạ
    // Electron gắn vào đây để bắn thông báo Windows. CỐ Ý chỉ truyền LOẠI sự kiện —
    // không tên, không nội dung: thông báo hệ thống hiện trên màn hình khóa và lưu vào
    // trung tâm thông báo, nên tin nhắn đã mã hóa đầu cuối không được rò ra qua đường đó.
    this.onNotify = null;            // (loai) => void  —  "message" | "approval" | "connected"
    this.webAddr = null;             // địa chỉ đang hiện trong mã QR (khóa chế độ web theo mạng con đó)
    this.webMoToi = 0;               // mốc thời gian chế độ web còn mở tới
    this.aiTaiWeb = new Map();       // ip -> {lan, luc} — ai đã tải mã của chế độ web
  }

  // --------------------------------------------------- khóa chế độ web theo card mạng
  /** Địa chỉ đang hiện trong mã QR — chỉ mạng con của nó mới tải được mã web.
   *  Mở cửa sổ QR cũng là lúc "mở cửa" cho chế độ web trong một khoảng thời gian. */
  datDiaChiWeb(ip) {
    const d = localIps().find((x) => x.ip === ip);
    this.webAddr = d ? { ip: d.ip, iface: d.iface, netmask: d.netmask } : null;
    this.webMoToi = Date.now() + Node.WEB_MO_MS;
    // Mỗi lần mở cửa sổ QR là một lượt ghép đôi mới — đếm lại từ đầu, và quên nền ARP
    // cũ vì đổi mạng thì MAC đổi là chuyện bình thường.
    this.aiTaiWeb = new Map();
    quenNenArp();
    this.pushState();
  }

  /** Máy ở địa chỉ này có được tải mã của chế độ web không? */
  choPhepWeb(remoteAddress) {
    const ip = String(remoteAddress || "").replace(/^::ffff:/, "");
    if (ip === "::1" || ip.startsWith("127.")) return { duoc: true };   // chính máy này

    // Chỉ mở trong lúc đang ghép đôi. Mã web nằm phơi 24/7 thì kẻ tấn công muốn ra tay lúc
    // nào cũng được; gói lại trong vài chục phút quanh lúc bạn thật sự quét QR thì nó phải
    // có mặt và ra tay đúng khoảnh khắc đó. Đang trò chuyện với một máy web thì vẫn để mở,
    // kẻo trình duyệt điện thoại nạp lại trang giữa chừng là đứt.
    const dangChatWeb = !!(this.session?.ready && this.peerMeta?.listenPort == null);
    if (!dangChatWeb && Date.now() > (this.webMoToi || 0)) {
      return { duoc: false, ly: "Chế độ web chỉ mở trong lúc ghép đôi, và cửa sổ đó đã hết hạn." };
    }

    const ds = localIps();
    // Card đã chọn có thể đã biến mất (tắt điểm phát sóng, rút cáp). Bám theo nó nữa là
    // khóa cứng mọi đường mà người dùng không hiểu vì sao — rơi về card tốt nhất hiện có.
    const conSong = this.webAddr && ds.some((x) => x.ip === this.webAddr.ip);
    // Chưa mở cửa sổ QR lần nào thì chưa có ý định cho ai vào — mặc định là card tốt nhất,
    // chứ không mở toang cho mọi card.
    const w = conSong ? this.webAddr : (ds[0] || null);
    if (!w) return { duoc: false, ly: "Máy tính chưa có địa chỉ mạng nào dùng được." };

    if (!cungMangCon(ip, w.ip, w.netmask)) {
      return { duoc: false, ly: `Thiết bị của bạn (${ip}) không cùng mạng với địa chỉ đang được `
        + `chia sẻ (${w.ip}${w.iface ? " — " + w.iface : ""}).` };
    }
    return { duoc: true };
  }

  /** Ghi lại thiết bị nào vừa tải mã của chế độ web. */
  ghiTaiWeb(remoteAddress) {
    const ip = String(remoteAddress || "").replace(/^::ffff:/, "");
    if (ip === "::1" || ip.startsWith("127.")) return;      // giao diện của chính máy
    const cu = this.aiTaiWeb.get(ip) || { lan: 0, luc: 0 };
    this.aiTaiWeb.set(ip, { lan: cu.lan + 1, luc: Date.now() / 1000 });
  }

  /** Phiên hiện tại có còn sống không? (socket mở và còn phản hồi nhịp tim) */
  isPeerAlive() {
    if (!this.peerWs) return false;
    const OPEN = 1;
    if (this.peerWs.readyState !== OPEN) return false;
    if (this._lastPong && Date.now() - this._lastPong > 45000) return false;
    return true;
  }

  forceTeardown(reason) { this._teardown(reason); }

  /** Nhịp tim: phát hiện đối phương biến mất mà không đóng socket tử tế. */
  _startHeartbeat(ws) {
    this._lastPong = Date.now();
    clearInterval(this._hb);
    this._hb = setInterval(() => {
      if (!this.peerWs || this.peerWs.readyState !== 1) { clearInterval(this._hb); return; }
      if (Date.now() - this._lastPong > 45000) {
        this._teardown("Đối phương không phản hồi — đã ngắt phiên.");
        clearInterval(this._hb);
        return;
      }
      try { this.peerWs.ping(); } catch { /* */ }
    }, 15000);
    if (typeof ws.on === "function") ws.on("pong", () => { this._lastPong = Date.now(); });
  }

  // ------------------------------------------------------------------ UI
  uiBroadcast(obj) {
    const s = JSON.stringify(obj);
    for (const ws of this.uiClients) {
      try { ws.send(s); } catch { this.uiClients.delete(ws); }
    }
  }
  _sessionLog(step, detail) { this.uiBroadcast({ type: "log", step, detail }); }

  state() {
    // Còn khóa thì KHÔNG để lọt gì ra giao diện — chưa nhập mật khẩu thì ngay cả tên
    // thiết bị hay danh sách liên hệ cũng không phải việc của người đang ngồi trước máy.
    if (this.storage.locked) {
      return { type: "state", locked: true, has_account: true };
    }
    let conn = null;
    if (this.session && this.session.ready) {
      conn = {
        connected: true,
        peer_name: this.peerMeta.name || "?",
        peer_pub: this.session.peer.id_pub,
        peer_fp: fingerprint(this.session.peer.id_pub),
        trusted: this.session.trusted,
        safety: this.session.safety,
      };
    }
    return {
      type: "state",
      identity: {
        pub: this.storage.idPub,
        fp: fingerprint(this.storage.idPub),
        name: this.storage.name,
        created: this.storage.identity.created,
        archived: this.storage.identity.archived.length,
      },
      // MỌI cuộc trò chuyện còn lịch sử, không chỉ khóa đã ghim — xem listConversations().
      contacts: this.storage.listConversations().map((c) => ({ ...c, last: this.storage.lastMessage(c.pub) })),
      trash: this.storage.listTrash(),
      peers: this.peers,
      pair_code: this.pairCode,
      self_port: this.port,
      strict_mode: !!this.storage.settings.strictMode,
      locked: false,
      has_account: this.storage.hasAccount,
      web_addr: this.webAddr,
      web_mo_toi: this.webMoToi,
      // Ai đã tải mã của chế độ web trong lượt ghép đôi này. Người dùng biết rõ mình có
      // mấy cái điện thoại — thấy 2 thiết bị trong khi chỉ cầm 1 là dấu hiệu rõ ràng.
      web_fetchers: [...this.aiTaiWeb.entries()].map(([ip, v]) => ({ ip, ...v })),
      ra_mang: this.webAddr ? raMang(this.webAddr.ip, this.webAddr.netmask) : null,
      lan_ips: ganNhan(localIps()),
      connection: conn,
    };
  }
  pushState() { this.uiBroadcast(this.state()); }

  // ------------------------------------------------------------ discovery
  startDiscovery() {
    this.discovery = new Discovery({
      nodeId: this.nodeId, name: this.storage.name, fp: fingerprint(this.storage.idPub),
      pub: this.storage.idPub, port: this.port,
      onChange: (peers) => { this.peers = peers; this.uiBroadcast({ type: "peers", peers }); },
    });
    this.discovery.start();
  }
  async _republish() {
    if (!this.discovery) return;
    await this.discovery.updateProps({
      name: this.storage.name, fp: fingerprint(this.storage.idPub), pub: this.storage.idPub,
    });
  }

  // --------------------------------------------------------- lệnh từ UI
  async handleUi(cmd) {
    // Khi còn khóa, CHỈ ba lệnh này chạy được. Chặn ở một chỗ duy nhất thay vì rải
    // kiểm tra khắp nơi — thêm lệnh mới về sau cũng tự động được chặn.
    const KHI_KHOA = new Set(["get_state", "unlock", "import_account"]);
    if (this.storage.locked && !KHI_KHOA.has(cmd.cmd)) {
      this.uiBroadcast({ type: "notice", text: "Hãy nhập mật khẩu để mở khóa trước.", bad: true });
      return;
    }
    switch (cmd.cmd) {
      case "get_state": this.pushState(); break;
      case "unlock": await this.unlock(cmd.password || ""); break;
      case "lock": this.lock(); break;
      case "create_account": await this.taiKhoan(() => this.storage.createAccount(cmd.password),
        "Đã đặt mật khẩu cho máy này. Lần mở app sau sẽ phải nhập mật khẩu.", "account_ok"); break;
      case "change_password": await this.taiKhoan(() => this.storage.changePassword(cmd.old_password, cmd.password),
        "Đã đổi mật khẩu.", "account_ok"); break;
      case "remove_account": await this.taiKhoan(() => this.storage.removeAccount(cmd.password),
        "Đã bỏ mật khẩu. Khóa quay lại chế độ bảo vệ bằng tài khoản Windows.", "account_ok"); break;
      case "export_account":
        await this.taiKhoan(() => {
          this.uiBroadcast({ type: "account_file", data: this.storage.exportAccount(cmd.password || null) });
        }, "Đã lưu tệp sao lưu (đã mã hóa bằng mật khẩu).", "account_ok");
        break;
      // Màn khóa dùng lệnh này — CHỈ nhận tệp .sen có mật khẩu. Không nhận bản sao lưu
      // bản rõ đời cũ, kẻo ai cầm máy cũng nhập đại một tệp vào là qua mặt màn khóa.
      case "import_account": await this.nhapTaiKhoan(cmd.data, cmd.password || ""); break;
      // Lệnh này chỉ chạy khi ĐÃ mở khóa, nên nhận được cả tệp sao lưu bản rõ đời cũ.
      case "import_file": await this.nhapTep(cmd.data, cmd.password || ""); break;
      case "set_name":
        this.storage.setName(cmd.name);
        await this._republish();
        this.pushState();
        break;
      case "rotate_key":
        this.storage.rotateIdentity();
        await this._republish();
        this.uiBroadcast({ type: "notice", text: "Đã xoay khóa danh tính. Liên hệ cần quét lại QR của bạn." });
        this.pushState();
        break;
      case "pin_key": {
        this.storage.pinContact(cmd.pub, cmd.name || "", cmd.host || null, cmd.port || null);
        if (cmd.pair_code) this.scannedPairCode = cmd.pair_code;  // để chứng minh khi họ gọi sang
        // Không báo ở đây: giao diện đã hiện một thông báo đầy đủ hơn (kèm bước tiếp theo),
        // thêm dòng nữa là hai thông báo chồng nhau.
        this.pushState();
        break;
      }
      case "set_web_addr": this.datDiaChiWeb(cmd.ip); break;
      case "new_pair_code":
        this.pairCode = newPairCode();
        this.pushState();
        break;
      case "connect":
        this.connectPeer(cmd.host, Number(cmd.port), cmd.expect_pub || null, cmd.pair_code || null);
        break;
      case "approve_peer": this.approveIncoming(); break;
      case "reject_peer": this._rejectIncoming(this.pendingApproval?.msg, "Bạn đã từ chối."); break;
      case "set_strict":
        this.storage.setSetting("strictMode", !!cmd.value);
        this.uiBroadcast({ type: "notice", text: cmd.value
          ? "Đã bật: chỉ nhận kết nối từ liên hệ đã ghim khóa."
          : "Đã tắt chế độ chặt: thiết bị lạ có thể xin kết nối (bạn vẫn phải duyệt)." });
        this.pushState();
        break;
      case "disconnect": this._teardown("Bạn đã ngắt kết nối."); break;
      case "delete_chat": this.deleteChat(cmd.pub, cmd.fp, cmd.name); break;
      case "restore_chat": this.restoreChat(cmd.fp); break;
      case "purge_chat": this.purgeChat(cmd.fp); break;
      case "send_text": this.sendText(cmd.text || ""); break;
      // Đường cũ (JSON+base64) — giữ cho tương thích; giao diện nay gửi khung nhị phân.
      case "send_file": await this.sendFile(cmd.name, cmd.mime || "", Buffer.from(cmd.data_b64 || "", "base64")); break;
      case "load_history":
        this.uiBroadcast({ type: "history", peer_pub: cmd.peer_pub, items: this.storage.loadHistory(cmd.peer_pub) });
        break;
      case "search": this.search(cmd.q || "", cmd.peer_pub || null); break;
    }
  }

  // ------------------------------------------------------ tài khoản cục bộ
  /** Chạy một thao tác tài khoản, báo lỗi ra giao diện thay vì ném lên trên.
   *  Lỗi ở đây gần như luôn là "sai mật khẩu" — người dùng cần đọc được câu đó. */
  async taiKhoan(viec, loiNhan, dau) {
    try {
      await viec();
      this.uiBroadcast({ type: "notice", text: loiNhan });
      if (dau) this.uiBroadcast({ type: dau });
      this.pushState();
    } catch (e) {
      this.uiBroadcast({ type: "notice", text: e.message, bad: true });
      this.uiBroadcast({ type: "account_fail" });
    }
  }

  async unlock(matKhau) {
    try {
      await this.storage.unlock(matKhau);
    } catch (e) {
      this.uiBroadcast({ type: "unlock_fail", text: e.message });
      return;
    }
    this.moKhoaXong();
  }

  /** Những việc phải hoãn lại cho tới khi có khóa: quảng bá mDNS và nhận kết nối. */
  moKhoaXong() {
    if (!this.discovery) this.startDiscovery();
    else this._republish();
    this.uiBroadcast({ type: "unlocked" });
    this.pushState();
  }

  lock() {
    if (!this.storage.hasAccount) return;
    this._teardown(null, true);
    try { this.discovery?.stop(); } catch { /* */ }
    this.discovery = null;
    this.peers = [];
    this.storage.lock();
    this.uiBroadcast({ type: "notice", text: "Đã khóa. Nhập mật khẩu để dùng tiếp." });
    this.pushState();
  }

  /** Phục hồi từ tệp khi app đang mở: nhận cả tệp .sen mới lẫn bản sao lưu bản rõ đời cũ. */
  async nhapTep(data, matKhau) {
    if (data?.kind === "sentinell-account") { await this.nhapTaiKhoan(data, matKhau); return; }
    await this.taiKhoan(async () => {
      this.storage.importBackup(data);
      await this._republish();
    }, "Đã phục hồi danh tính từ tệp sao lưu đời cũ (tệp đó KHÔNG được mã hóa — nên xóa đi).",
    "account_ok");
  }

  async nhapTaiKhoan(data, matKhau) {
    try {
      const r = await this.storage.importAccount(data, matKhau);
      this.uiBroadcast({ type: "notice",
        text: `Đã nhận tài khoản "${r.name}" (${r.contacts} liên hệ đã ghim). `
          + "Lịch sử tin nhắn KHÔNG đi kèm — tệp tài khoản chỉ mang khóa và danh bạ." });
      this.moKhoaXong();
    } catch (e) {
      this.uiBroadcast({ type: "unlock_fail", text: e.message });
    }
  }

  // ------------------------------------------------------- kết nối peer
  connectPeer(host, port, expectPub, pairCode = null) {
    if (this.session) this._teardown("Chuyển sang kết nối mới.");
    this.expectPub = expectPub;
    this.peerAddr = { host, port };
    const ws = new WebSocket(`ws://${host}:${port}/peer`, { maxPayload: 8 * 1024 * 1024 });
    ws.on("error", (e) => this.uiBroadcast({
      type: "notice", bad: true,
      text: `Không kết nối được tới ${host}:${port} — ${dichLoiMang(e)}`,
    }));
    ws.on("open", () => this.attachPeer(ws, "I", expectPub, pairCode));
  }

  /** Gắn một WebSocket peer (inbound hoặc outbound) vào phiên mới và chạy handshake. */
  attachPeer(ws, role, expectPub, pairCode = null) {
    this.sessionRole = role;
    this.session = new Session({
      role, idPriv: this.storage.idPriv, idPub: this.storage.idPub,
      name: this.storage.name, onLog: (s, d) => this._sessionLog(s, d),
      listenPort: this.port,             // báo cổng của tôi để đối phương gọi lại được
      pairCode: pairCode || this.scannedPairCode,   // mã tôi đã quét của họ (nếu có)
      activePairCode: this.pairCode,     // mã tôi đang hiện, để kiểm chứng minh của họ
    });
    // Kết nối đến (inbound): ghi lại IP để còn gọi lại được sau này.
    if (role === "R" && !this.peerAddr) {
      const ip = (ws._socket && ws._socket.remoteAddress || "").replace(/^::ffff:/, "");
      this.peerAddr = ip ? { host: ip, port: null } : null;
    }
    this.peerWs = ws;
    this._incoming = new Map();
    ws.on("message", (data, isBinary) => {
      // Khối tệp đi bằng khung nhị phân; mọi thứ còn lại vẫn là JSON dạng chữ.
      if (isBinary || isBinaryFrame(data)) { this._onPeerBinary(data); return; }
      let msg;
      try { msg = JSON.parse(data.toString()); } catch { return; }
      this._onPeerMsg(msg, expectPub).catch((e) =>
        this.uiBroadcast({ type: "notice", text: `Lỗi khi xử lý dữ liệu từ thiết bị kia: ${e.message}`, bad: true }));
    });
    this._startHeartbeat(ws);
    ws.on("close", () => { if (this.peerWs === ws) this._teardown("Đối phương đã ngắt kết nối.", true); });
    ws.on("error", () => {});
    ws.send(JSON.stringify(this.session.hello()));
  }

  async _onPeerMsg(msg, expectPub) {
    const s = this.session;
    if (!s) return;
    switch (msg.type) {
      case "hs": {
        this.peerMeta = { name: msg.name || "?", listenPort: msg.listen_port || null };
        // Đối phương khai báo cổng lắng nghe → ghi lại để sau này CHỦ ĐỘNG gọi sang được.
        if (this.peerAddr && !this.peerAddr.port && msg.listen_port) this.peerAddr.port = msg.listen_port;

        // KIỂM SOÁT KẾT NỐI ĐẾN: chỉ áp dụng cho phía nhận (role "R").
        // Trước đây bất kỳ ai chung mạng cũng tự kết nối vào được mà không phải hỏi ai.
        if (this.sessionRole === "R") {
          const known = this.storage.contactByPub(msg.id_pub);
          if (!known) {
            if (this.storage.settings.strictMode) {
              this._rejectIncoming(msg, "Thiết bị này chỉ nhận kết nối từ liên hệ đã ghim khóa.");
              return;
            }
            this._askApproval(msg);   // chờ người dùng bấm Chấp nhận/Từ chối
            return;
          }
        }
        this.peerWs.send(JSON.stringify(s.onHello(msg)));
        break;
      }
      case "rejected": {
        this.uiBroadcast({ type: "notice", text: `Thiết bị kia từ chối kết nối: ${msg.reason || ""}`, bad: true });
        // Đã báo cụ thể ở trên → dọn phiên KHÔNG kèm lý do, kẻo hiện hai thông báo chồng nhau.
        this._teardown(null);
        break;
      }
      case "pending": {
        this.uiBroadcast({
          type: "notice",
          text: `⏳ Đang chờ thiết bị kia bấm "Chấp nhận" — ${msg.reason || ""}`,
        });
        break;
      }
      case "hs-sig": {
        // Chữ ký của đối phương có thể tới TRƯỚC khi người dùng kịp bấm duyệt
        // (lúc đó ta chưa gọi onHello nên session.peer còn rỗng) → giữ lại, xử lý sau.
        if (this.pendingApproval || !s.peer) {
          this._deferredSig = msg;
          return;
        }
        let pinned = expectPub;
        if (pinned == null) {
          const c = this.storage.contactByPub(s.peer.id_pub);
          pinned = c ? c.pub : null;
        }
        s.onSig(msg, pinned);
        if (s.authFailed) {
          this.uiBroadcast({ type: "notice", text: "❌ Xác thực thất bại — khóa của thiết bị kia KHÔNG khớp khóa bạn đã ghim. "
            + "Có thể có kẻ mạo danh chen vào. Đã hủy kết nối.", bad: true });
          this._teardown(null);
          return;
        }
        // GHIM HAI CHIỀU: nếu họ chứng minh đã quét mã của tôi, hoặc tôi đã ghim họ từ trước,
        // thì lưu (hoặc cập nhật) họ vào danh bạ kèm địa chỉ → lần sau bấm "Nhắn lại" là xong.
        if (s.peerProvedPair || s.trusted || this.storage.contactByPub(s.peer.id_pub)) {
          const c = this.storage.pinContact(
            s.peer.id_pub, this.peerMeta.name || "",
            this.peerAddr?.host || null, this.peerAddr?.port || null,
          );
          if (s.peerProvedPair) {
            this.uiBroadcast({ type: "notice", text: `Đã ghép đôi với "${c.name}" — từ nay hai bên nhắn lại được mà không cần quét lại.` });
            this.pairCode = newPairCode(); // mã dùng một lần: đổi ngay sau khi ghép thành công
          }
        }
        // Ghi tên MỌI thiết bị từng nói chuyện, kể cả chưa ghim khóa — nếu không thì
        // cuộc trò chuyện đó không có chỗ nào trong cột bên trái, dù lịch sử vẫn nằm
        // trên máy và tìm kiếm vẫn ra.
        this.storage.rememberPeer(
          s.peer.id_pub, this.peerMeta.name || "",
          this.peerAddr?.host || null, this.peerAddr?.port || null,
        );
        this.uiBroadcast({ type: "connected", connection: this.state().connection });
        this.onNotify?.("connected");
        this.uiBroadcast({ type: "history", peer_pub: s.peer.id_pub, items: this.storage.loadHistory(s.peer.id_pub) });
        this.pushState();
        break;
      }
      case "msg": {
        let obj;
        try { obj = s.decrypt(msg); }
        catch { this.uiBroadcast({ type: "notice", text: "Một tin nhắn đến bị hỏng hoặc đã bị sửa trên đường truyền — đã bỏ qua để an toàn.", bad: true }); return; }
        await this._onPlainIncoming(obj);
        break;
      }
      case "busy":
        this.uiBroadcast({ type: "notice", text: "Thiết bị kia đang bận — họ đang trò chuyện với một máy khác.", bad: true });
        break;
    }
  }

  /** Hỏi người dùng có cho thiết bị lạ này kết nối không (60 giây, hết giờ thì từ chối). */
  /** Xóa hẳn một cuộc trò chuyện: tin nhắn đã lưu + khóa đã ghim.
   *  Đang chat với chính người đó thì ngắt trước, kẻo vừa xóa xong lại hiện lại. */
  deleteChat(pub, fp, ten) {
    if (!pub) return;
    const c = this.storage.contactByPub(pub);
    // Liên hệ chưa ghim thì không có trong danh bạ → lấy tên UI gửi lên, rồi mới tới tên phiên.
    ten = ten || c?.name || this.peerMeta?.name || "liên hệ";
    // Ngắt phiên KHÔNG kèm lý do: ngay dưới đã có thông báo đầy đủ rồi, kẻo hiện hai lần.
    if (this.session?.peer?.id_pub === pub) this._teardown(null);
    const so = this.storage.trashChat(pub, ten);
    this.uiBroadcast({ type: "notice",
      text: `Đã chuyển cuộc trò chuyện với "${ten}" vào mục Đã xóa (${so} tin). `
        + "Vào cuối danh sách trò chuyện để khôi phục hoặc xóa hẳn." });
    this.pushState();
  }

  restoreChat(fp) {
    const t = this.storage.restoreChat(fp);
    if (!t) return;
    this.uiBroadcast({ type: "notice",
      text: `Đã khôi phục cuộc trò chuyện với "${t.name}".`
        + (t.was_pinned ? " Khóa đã ghim cũng được trả lại." : "") });
    this.pushState();
  }

  purgeChat(fp) {
    const t = this.storage.purgeChat(fp);
    if (!t) return;
    this.uiBroadcast({ type: "notice", text: `Đã xóa vĩnh viễn cuộc trò chuyện với "${t.name}".` });
    this.pushState();
  }

  _askApproval(msg) {
    const fp = fingerprint(msg.id_pub);
    this.pendingApproval = {
      msg,
      timer: setTimeout(() => this._rejectIncoming(msg, "Không có phản hồi (hết thời gian chờ)."), 60000),
    };
    // Nói rõ cho bên gọi biết vì sao phải chờ — nếu không họ chỉ thấy "đang kết nối"
    // đứng im cả phút rồi tự rớt, không hiểu chuyện gì đang xảy ra.
    try {
      this.peerWs?.send(JSON.stringify({
        type: "pending",
        reason: "họ đang được hỏi có chấp nhận kết nối này không.",
      }));
    } catch { /* socket có thể đã đóng */ }
    this.uiBroadcast({
      type: "approval_request",
      name: msg.name || "?", fp, pub: msg.id_pub,
      host: this.peerAddr?.host || null,
    });
    this.onNotify?.("approval");
  }

  /** Người dùng bấm "Chấp nhận" → tiếp tục bắt tay như bình thường. */
  approveIncoming() {
    const p = this.pendingApproval;
    if (!p || !this.session || !this.peerWs) return;
    clearTimeout(p.timer);
    this.pendingApproval = null;
    this.uiBroadcast({ type: "approval_done" });
    this.peerWs.send(JSON.stringify(this.session.onHello(p.msg)));
    // Nếu chữ ký của họ đã tới sớm và đang được giữ, xử lý ngay bây giờ.
    const deferred = this._deferredSig;
    this._deferredSig = null;
    if (deferred) {
      this._onPeerMsg(deferred, null).catch((e) =>
        this.uiBroadcast({ type: "notice", text: `Lỗi khi xử lý dữ liệu từ thiết bị kia: ${e.message}`, bad: true }));
    }
  }

  /** Từ chối: báo cho bên kia biết rồi đóng, thay vì im lặng bỏ mặc. */
  _rejectIncoming(msg, reason) {
    const p = this.pendingApproval;
    if (p) clearTimeout(p.timer);
    this.pendingApproval = null;
    this.uiBroadcast({ type: "approval_done" });
    try { this.peerWs?.send(JSON.stringify({ type: "rejected", reason })); } catch { /* */ }
    this.uiBroadcast({ type: "notice", text: `Đã từ chối kết nối từ "${msg?.name || "thiết bị lạ"}". ${reason}` });
    this._teardown(null);
  }

  async _onPlainIncoming(obj) {
    const peerPub = this.session.peer.id_pub;
    // Bẫy dây bên trang web báo về. Phản ứng PHẢI xảy ra ở đây — phản ứng chạy trong đoạn
    // mã đã bị chiếm thì vô nghĩa (mã đã bị sửa sẽ không tự sát).
    if (obj.type === "canary") {
      const ds = Array.isArray(obj.nghi) ? obj.nghi.slice(0, 8).map(String) : [];
      this.uiBroadcast({ type: "notice", bad: true,
        text: "🚨 ĐÃ NGẮT KẾT NỐI — trang web trên thiết bị kia đang chạy trong môi trường bị "
          + `can thiệp: ${ds.join("; ")}. Có thể có kẻ đã sửa mã trang trên đường truyền. `
          + "Hãy chuyển sang nối trực tiếp (điểm phát sóng hoặc cáp USB) rồi thử lại. "
          + "Nếu thiết bị kia có cài tiện ích mở rộng cho trình duyệt thì đó cũng là một "
          + "nguyên nhân có thể — hãy thử bằng cửa sổ riêng tư." });
      this._sessionLog("verify-fail", "Bẫy dây báo động: " + ds.join("; "));
      this._teardown(null);
      return;
    }
    if (obj.type === "text") {
      const ts = this.storage.saveMessage(peerPub, "in", obj);
      this.uiBroadcast({ type: "message", direction: "in", ts, body: obj });
      this.onNotify?.("message");
    } else if (obj.type === "file-meta") {
      // Kiểm TRƯỚC khi cấp phát: mọi con số ở đây là do máy bên kia nói.
      const loi = loiMoTaTep(obj);
      if (loi) {
        this.uiBroadcast({ type: "notice", bad: true,
          text: `Thiết bị kia gửi một mô tả tệp không hợp lệ (${loi}) — đã bỏ qua.` });
        return;
      }
      if (this._incoming.size >= SO_TEP_NHAN_CUNG_LUC) {
        this.uiBroadcast({ type: "notice", bad: true,
          text: "Thiết bị kia đang gửi quá nhiều tệp cùng lúc — đã bỏ qua bớt." });
        return;
      }
      this._incoming.set(obj.name, { meta: obj, chunks: new Array(obj.chunks).fill(null), recv: 0 });
      this.tienDo("in", obj.name, 0, obj.chunks, obj.size);
    } else if (obj.type === "file-chunk") {
      // Đường JSON+base64 — chỉ còn dùng khi đối phương là node Python tham chiếu.
      this._nhanKhoi(obj.name, obj.idx, Buffer.from(obj.data, "base64"), peerPub);
    }
  }

  /** Khung nhị phân từ peer: chỉ dùng cho khối tệp. */
  _onPeerBinary(frame) {
    const s = this.session;
    if (!s || !s.ready) return;
    let r;
    try {
      r = s.decryptBinary(frame, true);        // tự ghi nhật ký gọn bên dưới, khỏi 40 dòng giống nhau
    } catch {
      this.uiBroadcast({ type: "notice", bad: true,
        text: "Một khối tệp đến bị hỏng hoặc đã bị sửa trên đường truyền — đã bỏ qua để an toàn." });
      return;
    }
    if (r.mtype !== "file-chunk") return;
    if (r.meta.idx === 0) {
      this._sessionLog("decrypt", `Nhận khối tệp đầu tiên: giải mã AES-256-GCM + kiểm toàn vẹn OK (seq=${r.seq}), `
        + "dữ liệu đi thẳng dạng bytes — không qua base64/hex.");
    }
    this._nhanKhoi(r.meta.name, r.meta.idx, Buffer.from(r.bytes), s.peer.id_pub);
  }

  /** Gộp một khối vào tệp đang nhận dở (dùng chung cho cả hai đường truyền). */
  _nhanKhoi(name, idx, buf, peerPub) {
    const ent = this._incoming.get(name);
    if (!ent || ent.chunks[idx] !== null) return;     // khối lạ hoặc trùng thì bỏ
    ent.chunks[idx] = buf;
    ent.recv++;
    this.tienDo("in", name, ent.recv, ent.meta.chunks, ent.meta.size);
    if (ent.recv === ent.meta.chunks) {
      this._assembleFile(ent, peerPub);
      this._incoming.delete(name);
    }
  }

  /** Báo giao diện tiến độ truyền tệp. Tệp lớn giờ chạy nhanh nhưng vẫn mất vài giây —
   *  không có dòng này thì người dùng tưởng app đứng. */
  tienDo(huong, name, xong, tong, size = 0) {
    this.uiBroadcast({ type: "file_progress", dir: huong, name, done: xong, total: tong, size });
  }

  _assembleFile(ent, peerPub) {
    const data = Buffer.concat(ent.chunks);
    const meta = ent.meta;
    const ok = crypto.createHash("sha256").update(data).digest("hex") === meta.hash;
    const safe = path.basename(meta.name).replace(/\.\./g, "_");
    const fname = `${crypto.randomBytes(4).toString("hex")}_${safe}`;
    fs.writeFileSync(path.join(this.storage.filesDir, fname), data);
    const body = { type: "file", name: meta.name, size: meta.size, mime: meta.mime || "", url: `/file/${fname}`, integrity: ok };
    const ts = this.storage.saveMessage(peerPub, "in", body);
    this.uiBroadcast({ type: "message", direction: "in", ts, body });
    this.onNotify?.("message");
  }

  /** Tìm trong lịch sử và gắn sẵn tên liên hệ cho từng kết quả, để giao diện khỏi
   *  phải tra ngược từ khóa công khai. */
  search(q, peerPub = null) {
    const kq = this.storage.searchMessages(q, { peerPub, limit: 60 });
    const ten = new Map(this.storage.listConversations().map((c) => [c.pub, c.name]));
    const items = kq.items.map((m) => {
      const fp = fingerprint(m.peer_pub);
      return { ...m, peer_fp: fp, peer_name: ten.get(m.peer_pub) || `Thiết bị ${fp.slice(0, 6)}` };
    });
    this.uiBroadcast({ type: "search_results", q, items, scanned: kq.scanned, truncated: kq.truncated });
  }

  sendText(text) {
    text = String(text).trim();
    if (!text || !(this.session && this.session.ready)) return;
    this.peerWs.send(JSON.stringify(this.session.encrypt("text", { text })));
    const body = { type: "text", text };
    const ts = this.storage.saveMessage(this.session.peer.id_pub, "out", body);
    this.uiBroadcast({ type: "message", direction: "out", ts, body });
  }

  async sendFile(name, mime, data) {
    if (!(this.session && this.session.ready)) return;
    const s = this.session, ws = this.peerWs;
    const hash = crypto.createHash("sha256").update(data).digest("hex");
    const chunks = Math.max(1, Math.ceil(data.length / CHUNK));
    const nhiPhan = s.peerBinary;

    // Hiện bong bóng ngay, trước khi truyền: tệp lớn mất vài giây, để trống thì
    // người gửi không biết máy đã nhận lệnh hay chưa.
    const safe = path.basename(name).replace(/\.\./g, "_");
    const fname = `${crypto.randomBytes(4).toString("hex")}_${safe}`;
    fs.writeFileSync(path.join(this.storage.filesDir, fname), data);
    const body = { type: "file", name, size: data.length, mime, url: `/file/${fname}`, integrity: true };
    const ts = this.storage.saveMessage(s.peer.id_pub, "out", body);
    this.uiBroadcast({ type: "message", direction: "out", ts, body });

    ws.send(JSON.stringify(s.encrypt("file-meta", { name, size: data.length, mime, hash, chunks })));
    this.tienDo("out", name, 0, chunks, data.length);
    for (let i = 0; i < chunks; i++) {
      if (this.peerWs !== ws || ws.readyState !== 1) return;    // ngắt giữa chừng thì dừng
      const slice = data.subarray(i * CHUNK, (i + 1) * CHUNK);
      if (nhiPhan) ws.send(s.encryptBinary("file-chunk", { name, idx: i }, slice, i !== 0));
      else ws.send(JSON.stringify(s.encrypt("file-chunk", { name, idx: i, data: slice.toString("base64") })));
      this.tienDo("out", name, i + 1, chunks, data.length);
      await this._choVoiHangDoi(ws);
    }
    this._sessionLog("encrypt", `Gửi xong "${name}" — ${chunks} khối, MỖI khối một khóa ratchet riêng `
      + `(seq tiến ${chunks} bước). Kênh: ${nhiPhan ? "khung nhị phân (bytes thẳng)" : "JSON+base64 (bản cũ)"}.`);
  }

  /** Chờ hàng đợi socket vơi bớt trước khi nhồi tiếp — nếu không, cả tệp nằm trong RAM
   *  và mạng chậm thì bộ nhớ phình theo kích thước tệp chứ không theo tốc độ đường truyền. */
  _choVoiHangDoi(ws) {
    const TRAN = 4 * 1024 * 1024;
    if (!ws.bufferedAmount || ws.bufferedAmount < TRAN) return Promise.resolve();
    return new Promise((xong) => {
      const xem = setInterval(() => {
        if (ws.readyState !== 1 || ws.bufferedAmount < TRAN) { clearInterval(xem); xong(); }
      }, 20);
    });
  }

  _teardown(reason, silentIfNone = false) {
    const had = this.session !== null;
    if (this.peerWs) { try { this.peerWs.close(); } catch { /* */ } }
    this.session = null;
    this.peerWs = null;
    clearInterval(this._hb);
    if (this.pendingApproval) {
      clearTimeout(this.pendingApproval.timer);
      this.pendingApproval = null;
      // Phải báo UI gỡ hộp duyệt: bên xin kết nối có thể đã tắt app / rớt mạng,
      // để nguyên thì hộp đứng đó hỏi về một yêu cầu không còn tồn tại.
      this.uiBroadcast({ type: "approval_done" });
    }
    this._deferredSig = null;
    this.peerMeta = {};
    this.peerAddr = null;
    this._incoming = new Map();
    if (had || !silentIfNone) {
      this.uiBroadcast({ type: "disconnected", reason });
      this.pushState();
    }
  }

  async stop() {
    this._teardown("Tắt app.", true);
    if (this.discovery) await this.discovery.stop();
  }
}
