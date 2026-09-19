// Kiểm những gì node PHƠI RA MẠNG, và việc khóa chế độ web theo card mạng.
// Máy chủ bind 0.0.0.0 để điện thoại vào được /join, nên phải biết chắc đường nào mở cho ai.
//
//   node scripts/test-lan.mjs
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import { startServer } from "../desktop/server/index.js";
import { localIp } from "../desktop/server/discovery.js";
import { doanNhanh, ganNhan, cungMangCon, MUC, phanTichLangGieng, quenNenArp } from "../desktop/server/mangcuc.js";

let loi = 0;
const dat = (t, ok, x = "") => {
  console.log(`${t.padEnd(54, " ")} ${ok ? "OK" : "SAI"}${x ? "   " + x : ""}`);
  if (!ok) loi++;
};

// ============================== phân loại mạng (không cần máy chủ)
console.log("--- phân loại mạng ---");
dat("192.168.137.x  →  nối trực tiếp (hotspot Windows)",
  doanNhanh("Local Area Connection* 8", "192.168.137.1") === MUC.TRUC_TIEP);
// Điểm phát sóng chạy CẢ HAI CHIỀU — máy tính không phát được thì điện thoại phát.
// Nhận ra được chiều ngược mới khuyên đúng cho người dùng iPhone (không có app riêng).
dat("172.20.10.x /28  →  nối trực tiếp (hotspot iPhone)",
  doanNhanh("Wi-Fi", "172.20.10.3", "255.255.255.240") === MUC.TRUC_TIEP);
dat("172.20.10.x nhưng SAI mặt nạ  →  không dám gắn nhãn an toàn",
  doanNhanh("Wi-Fi", "172.20.10.3", "255.255.0.0") !== MUC.TRUC_TIEP);
dat("192.168.43.x  →  nối trực tiếp (hotspot Android)",
  doanNhanh("Wi-Fi", "192.168.43.7") === MUC.TRUC_TIEP);
dat("nhãn nói rõ NHẬN RA CÁI GÌ, để người dùng tự kiểm chứng",
  ganNhan([{ ip: "172.20.10.3", iface: "Wi-Fi", netmask: "255.255.255.240" }])[0].y.includes("iPhone"));
// Máy KHÔNG CÓ card WiFi: iPhone chia sẻ qua cáp USB hiện ra như một card Ethernet,
// nhưng vẫn mang đúng dải 172.20.10.x/28 — phải nhận ra, vì đó là lối thoát duy nhất.
dat("iPhone qua CÁP USB (hiện như Ethernet)  →  trực tiếp",
  doanNhanh("Ethernet 2", "172.20.10.2", "255.255.255.240") === MUC.TRUC_TIEP);
dat("169.254.x.x    →  chưa có mạng",
  doanNhanh("Ethernet", "169.254.4.32") === MUC.CHUA_CO_MANG);
// Quan trọng nhất: báo nhầm "an toàn" nguy hiểm hơn hẳn báo nhầm "cẩn thận".
dat("WiFi thường KHÔNG bao giờ tự nhận là an toàn",
  doanNhanh("Wi-Fi", "192.168.1.9") !== MUC.TRUC_TIEP);
dat("mỗi nhãn đều kèm mức an toàn và lời giải thích",
  ganNhan([{ ip: "192.168.1.9", iface: "Wi-Fi" }]).every((d) => d.an && d.y && d.nhan));
dat("cùng mạng con /24", cungMangCon("192.168.137.5", "192.168.137.1", "255.255.255.0"));
dat("khác mạng con → không", !cungMangCon("192.168.1.9", "192.168.137.1", "255.255.255.0"));

// ---- mã QR phải MẶC ĐỊNH chọn đường trực tiếp khi máy đang có sẵn một đường như thế
{
  const that = os.networkInterfaces;
  const thu = async (mangChung, tenCard, tenCardTrucTiep) => {
    os.networkInterfaces = () => ({
      [tenCard]: [{ family: "IPv4", internal: false, address: mangChung, netmask: "255.255.0.0" }],
      [tenCardTrucTiep]: [{ family: "IPv4", internal: false, address: "172.20.10.2", netmask: "255.255.255.240" }],
    });
    const m = await import(`../desktop/server/discovery.js?v=${encodeURIComponent(mangChung + tenCardTrucTiep)}`);
    return m.localIp();
  };
  dat("mạng trường 10.x + iPhone cáp USB  →  QR chọn cáp USB",
    await thu("10.20.30.44", "Ethernet", "Ethernet 2") === "172.20.10.2");
  dat("mạng nhà 192.168.x + iPhone cáp USB  →  vẫn chọn cáp USB",
    await thu("192.168.1.44", "Ethernet", "Ethernet 2") === "172.20.10.2");
  // Card Bluetooth bị phạt nặng vì thường là card rác — nhưng khi nó mang địa chỉ
  // của một đường trực tiếp thật thì phạt nó là chọn nhầm đường kém an toàn hơn.
  dat("iPhone chia sẻ qua Bluetooth  →  vẫn được ưu tiên",
    await thu("192.168.1.44", "Ethernet", "Bluetooth Network Connection") === "172.20.10.2");
  os.networkInterfaces = that;
}

// ============================== rà dấu vết kẻ đứng giữa
// KHÔNG kiểm được tệp JS trên điện thoại có bị sửa không (phải hỏi chính đoạn mã đã bị sửa).
// Nhưng bắt được DẤU VẾT của cách chen vào phổ biến nhất trong LAN: giả mạo ARP.
console.log("\n--- rà dấu vết giả mạo ARP ---");
{
  const MASK = "255.255.255.0";
  const binhThuong = [
    { ip: "192.168.1.1", mac: "D4-9A-A0-95-DA-E0" },   // router
    { ip: "192.168.1.23", mac: "AA-BB-CC-11-22-33" },  // điện thoại
  ];
  quenNenArp();
  const r1 = phanTichLangGieng(binhThuong, "192.168.1.9", MASK);
  dat("mạng sạch  →  không báo động", r1.nghiNgo === false && r1.soLangGieng === 2);

  // Kẻ tấn công nhận mình vừa là router vừa là điện thoại — dấu hiệu kinh điển.
  quenNenArp();
  const gia = [
    { ip: "192.168.1.1", mac: "DE-AD-BE-EF-00-01" },
    { ip: "192.168.1.23", mac: "DE-AD-BE-EF-00-01" },
  ];
  const r2 = phanTichLangGieng(gia, "192.168.1.9", MASK);
  dat("một MAC đứng tên 2 IP  →  BÁO ĐỘNG", r2.nghiNgo === true);
  dat("lời cảnh báo gọi đúng tên hiện tượng",
    r2.dauHieu.join(" ").includes("giả mạo ARP"));

  // MAC của router đổi giữa chừng.
  quenNenArp();
  phanTichLangGieng(binhThuong, "192.168.1.9", MASK);          // ghi nền
  const r3 = phanTichLangGieng(
    [{ ip: "192.168.1.1", mac: "DE-AD-BE-EF-00-01" }], "192.168.1.9", MASK);
  dat("MAC của router đổi giữa chừng  →  BÁO ĐỘNG", r3.nghiNgo === true);
  dat("cảnh báo nói rõ địa chỉ nào vừa đổi", r3.dauHieu.join(" ").includes("192.168.1.1"));

  // Láng giềng ở mạng con KHÁC thì không liên quan — đừng báo động nhầm.
  quenNenArp();
  const r4 = phanTichLangGieng(
    [{ ip: "10.0.0.5", mac: "DE-AD-BE-EF-00-01" }, { ip: "10.0.0.6", mac: "DE-AD-BE-EF-00-01" }],
    "192.168.1.9", MASK);
  dat("trùng MAC ở mạng con khác  →  KHÔNG báo động nhầm", r4.nghiNgo === false);
}


// ---- CHỐNG LÀM SẬP: mọi con số trong `file-meta` là do ĐỐI PHƯƠNG nói.
//      Trước 3.15.0, `chunks: 50000000` là bên nhận cấp phát vài GB rồi chết.
console.log("\n--- chặn gói mô tả tệp độc hại ---");
{
  const { loiMoTaTep, SO_KHOI_TOI_DA } = await import("@sentinell/core");
  const ok = { name: "anh.png", chunks: 4, size: 1024 };
  dat("gói hợp lệ  →  qua", loiMoTaTep(ok) === null);
  dat("chunks khổng lồ  →  CHẶN", !!loiMoTaTep({ ...ok, chunks: 50_000_000 }));
  dat("chunks âm  →  chặn", !!loiMoTaTep({ ...ok, chunks: -1 }));
  dat("chunks không nguyên  →  chặn", !!loiMoTaTep({ ...ok, chunks: 1.5 }));
  dat("chunks là chuỗi  →  chặn", !!loiMoTaTep({ ...ok, chunks: "4" }));
  dat("đúng ngưỡng trên  →  vẫn qua", loiMoTaTep({ ...ok, chunks: SO_KHOI_TOI_DA }) === null);
  dat("trên ngưỡng một bậc  →  chặn", !!loiMoTaTep({ ...ok, chunks: SO_KHOI_TOI_DA + 1 }));
  dat("tên tệp rỗng  →  chặn", !!loiMoTaTep({ ...ok, name: "" }));
  dat("tên tệp dài vô lý  →  chặn", !!loiMoTaTep({ ...ok, name: "x".repeat(5000) }));
  dat("kích thước vượt mức  →  chặn", !!loiMoTaTep({ ...ok, size: 9e12 }));
  dat("lời từ chối nói rõ giới hạn", /MB/.test(loiMoTaTep({ ...ok, chunks: 9e6 }) || ""));
}

// ============================== phần cần máy chủ thật
const goc = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(goc, "../web");
const thuMuc = fs.mkdtempSync(path.join(os.tmpdir(), "sentinell-lan-"));
const S = await startServer({ dataDir: path.join(thuMuc, "data"), port: 8331, webDir });
const cong = S.port;
const ip = localIp();

const ket = async () => {
  await S.stop();
  fs.rmSync(thuMuc, { recursive: true, force: true });
  console.log(loi === 0 ? "\nTẤT CẢ ĐẠT" : `\n${loi} MỤC SAI`);
  process.exit(loi === 0 ? 0 : 1);
};

if (!ip || ip.startsWith("127.")) {
  console.log("\n(máy này không có địa chỉ LAN — bỏ qua phần kiểm tra qua mạng)");
  await ket();
}

/** Thử mở /ui từ một địa chỉ cho trước. */
const thuUi = (host) => new Promise((xong) => {
  const w = new WebSocket(`ws://${host}:${cong}/ui`);
  const gio = setTimeout(() => { try { w.close(); } catch { /* */ } xong({ noi: false, ly: "quá hạn" }); }, 3000);
  w.on("message", (d) => {
    const m = JSON.parse(d.toString());
    if (m.type === "state") { clearTimeout(gio); w.close(); xong({ noi: true, ten: m.identity?.name }); }
  });
  w.on("error", (e) => { clearTimeout(gio); xong({ noi: false, ly: e.message }); });
  w.on("close", () => { clearTimeout(gio); xong({ noi: false, ly: "bị đóng" }); });
});
const st = (u) => fetch(u).then((r) => r.status).catch(() => 0);

// ---- /ui là kênh ĐIỀU KHIỂN: đọc trạng thái, đọc lịch sử, gửi tin, xóa, xuất tài khoản.
//      Mở ra LAN là bất kỳ ai cùng mạng cũng chiếm được app mà không cần phá gì cả.
console.log("\n--- kênh điều khiển /ui ---");
const ngoai = await thuUi(ip);
dat("/ui từ ngoài LAN  →  BỊ CHẶN", ngoai.noi === false, ngoai.ly || "");
const trong = await thuUi("127.0.0.1");
dat("/ui từ trong máy  →  vẫn chạy", trong.noi === true, trong.ten || "");

// ---- /file/* là tệp đã nhận; chỉ giao diện ở 127.0.0.1 cần. Trang /join dựng blob: riêng.
dat("/file từ ngoài LAN  →  403",
  await st(`http://${ip}:${cong}/file/abcd1234_anh.png`) === 403);
dat("/file từ trong máy  →  404 (không phải 403)",
  await st(`http://127.0.0.1:${cong}/file/khong-co-that.png`) === 404);

// ---- khóa mã của chế độ web vào đúng mạng con đang chia sẻ
console.log("\n--- khóa chế độ web theo card mạng ---");
S.node.datDiaChiWeb(ip);                        // đang chia sẻ qua card thật đang dùng
const khac = ip.startsWith("192.168.137.") ? "10.7.7.7" : "192.168.137.9";
dat("máy ở mạng con khác  →  KHÔNG tải được mã web",
  S.node.choPhepWeb(khac).duoc === false);
dat("máy cùng mạng con  →  tải được",
  S.node.choPhepWeb(ip.replace(/\.\d+$/, ".231")).duoc === true);
dat("chính máy này (loopback) luôn được",
  S.node.choPhepWeb("127.0.0.1").duoc === true);
dat("lý do từ chối nói rõ địa chỉ bị chặn",
  String(S.node.choPhepWeb(khac).ly || "").includes(khac));

// Kiểm qua HTTP THẬT: khóa web vào một card khác, rồi gọi từ IP LAN hiện tại.
const cardKhac = S.node.constructor
  ? (await import("../desktop/server/discovery.js")).localIps()
    .find((d) => d.ip !== ip && !cungMangCon(ip, d.ip, d.netmask))
  : null;
if (cardKhac) {
  S.node.datDiaChiWeb(cardKhac.ip);
  dat(`qua HTTP thật: khóa vào ${cardKhac.iface} → /join từ WiFi bị 403`,
    await st(`http://${ip}:${cong}/join`) === 403);
  dat("qua HTTP thật: mã lõi cũng bị 403",
    await st(`http://${ip}:${cong}/vendor/protocol.bundle.js`) === 403);
} else {
  // Máy chỉ có một mạng con (Node chỉ liệt kê card đang kết nối) nên không dựng được
  // cảnh "gọi từ dải khác". Thay vào đó kiểm ĐÚNG chỗ nối: tầng HTTP có thật sự hỏi
  // choPhepWeb() không, và câu từ chối có ra trang giải thích không.
  const that = S.node.choPhepWeb.bind(S.node);
  S.node.choPhepWeb = () => ({ duoc: false, ly: "thử nghiệm" });
  dat("tầng HTTP có hỏi choPhepWeb()  →  /join 403",
    await st(`http://${ip}:${cong}/join`) === 403);
  const trang = await fetch(`http://${ip}:${cong}/join`).then((r) => r.text()).catch(() => "");
  dat("bị chặn thì trả TRANG GIẢI THÍCH, không phải lỗi trống",
    trang.includes("chế độ web") && trang.includes("mã QR"));
  S.node.choPhepWeb = that;
}

// Card đã chọn biến mất (tắt điểm phát sóng) thì phải rơi về card còn sống,
// chứ không khóa cứng mọi đường.
S.node.webAddr = { ip: "203.0.113.9", iface: "Card đã rút", netmask: "255.255.255.0" };
dat("card đã chọn biến mất  →  rơi về card còn sống",
  S.node.choPhepWeb(ip.replace(/\.\d+$/, ".231")).duoc === true);

// ---- chế độ web chỉ mở trong lúc ghép đôi
console.log("\n--- cửa sổ thời gian ---");
S.node.datDiaChiWeb(ip);
dat("vừa mở cửa sổ QR  →  tải được", S.node.choPhepWeb(ip.replace(/\.\d+$/, ".231")).duoc === true);
S.node.webMoToi = Date.now() - 1000;            // giả như đã quá hạn
const hetHan = S.node.choPhepWeb(ip.replace(/\.\d+$/, ".231"));
dat("quá hạn  →  KHÔNG tải được nữa", hetHan.duoc === false);
dat("lý do nói rõ phải mở lại mã QR", String(hetHan.ly || "").includes("ghép đôi"));
dat("quá hạn nhưng loopback vẫn vào được (giao diện của chính máy)",
  S.node.choPhepWeb("127.0.0.1").duoc === true);

S.node.datDiaChiWeb(ip);                        // chọn lại đúng card đang dùng
console.log("\n--- những đường điện thoại THẬT SỰ cần thì phải còn mở ---");
dat("/join  →  còn mở", await st(`http://${ip}:${cong}/join`) === 200);
dat("mã lõi  →  còn mở", await st(`http://${ip}:${cong}/vendor/protocol.bundle.js`) === 200);
dat("/api/info  →  còn mở", await st(`http://${ip}:${cong}/api/info`) === 200);
dat("/api/info có kèm nhãn an toàn từng card", await (async () => {
  const j = await fetch(`http://${ip}:${cong}/api/info`).then((r) => r.json());
  return (j.lan_ips || []).every((d) => d.muc && d.nhan && d.an);
})());

// ---- bẫy dây: máy tính phải NGẮT khi trang web báo môi trường bị can thiệp.
//      Phản ứng chỉ có nghĩa khi xảy ra Ở ĐÂY — chạy trong đoạn mã đã bị chiếm thì vô nghĩa.
console.log("\n--- bẫy dây (phản ứng phía máy tính) ---");
{
  const thuMuc2 = fs.mkdtempSync(path.join(os.tmpdir(), "sentinell-bay-"));
  const B = await startServer({ dataDir: path.join(thuMuc2, "data"), port: 8332, webDir });
  const suA = []; S.node.uiClients.add({ send: (s) => suA.push(JSON.parse(s)) });
  const suB = []; B.node.uiClients.add({ send: (s) => suB.push(JSON.parse(s)) });

  const cho = async (su, hop, han = 12000) => {
    const het = Date.now() + han;
    while (Date.now() < het) {
      const m = su.find(hop);
      if (m) return m;
      await new Promise((r) => setTimeout(r, 30));
    }
    return null;
  };

  S.node.connectPeer("127.0.0.1", B.port, null, null);
  await cho(suB, (m) => m.type === "approval_request");
  B.node.approveIncoming();
  dat("dựng được phiên để thử", !!await cho(suA, (m) => m.type === "connected"));

  // Giả trang web báo động qua ĐƯỜNG ĐÃ MÃ HÓA (đúng như join.js làm): bỏ gói thì `seq`
  // lệch và bên kia cảnh báo, sửa gói thì GCM từ chối — không bịt miệng lặng lẽ được.
  B.node.peerWs.send(JSON.stringify(
    B.node.session.encrypt("canary", { nghi: ["hàm WebSocket.send đã bị thay thế"] })));

  const bao = await cho(suA, (m) => m.type === "notice" && m.bad && /ĐÃ NGẮT KẾT NỐI/.test(m.text || ""));
  dat("nhận báo động  →  hiện cảnh báo đỏ", !!bao);
  dat("cảnh báo nói rõ dấu hiệu nào", /WebSocket\.send/.test(bao?.text || ""));
  dat("cảnh báo có gợi ý nối trực tiếp", /điểm phát sóng|cáp USB/.test(bao?.text || ""));
  dat("nhắc cả khả năng do tiện ích trình duyệt", /tiện ích/.test(bao?.text || ""));
  await new Promise((r) => setTimeout(r, 400));
  dat("phiên bị NGẮT thật, không chỉ cảnh báo suông", S.node.session === null);

  await B.stop();
  fs.rmSync(thuMuc2, { recursive: true, force: true });
}

await ket();
