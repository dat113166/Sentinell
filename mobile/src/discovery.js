// Tìm thiết bị Sentinell trong cùng mạng LAN bằng mDNS/DNS-SD (react-native-zeroconf; trên
// Android là NsdManager của hệ điều hành). Cùng loại dịch vụ `_sentinell._tcp` và cùng các khóa
// TXT (id, name, fp, pub) với desktop/discovery.js và bản Python — nên ba bên thấy nhau.
//
// Lưu ý bảo mật: TXT là do máy kia TỰ KHAI, không có chữ ký. Khóa `pub` trong đó chỉ để hiển
// thị, KHÔNG BAO GIỜ được dùng làm khóa đã ghim — ai cũng quảng bá được tên và khóa bất kỳ.
import { NativeModules } from "react-native";

const LOAI = "sentinell";

export function coTheTim() {
  return !!NativeModules.RNZeroconf;
}

export function batDauTim({ nodeId, name, fp, pub, port, onPeers, onLog }) {
  if (!coTheTim()) return null;
  const mod = require("react-native-zeroconf");
  const Zeroconf = mod.default || mod;
  const zc = new Zeroconf();
  const peers = new Map();       // id -> { id, name, fp, pub, host, port, _sname }
  const tenDichVu = `sentinell-${nodeId.slice(0, 10)}`;
  let thayChinhMinh = false;

  const bao = () => onPeers([...peers.values()].map(({ _sname, ...p }) => p));

  zc.on("resolved", (s) => {
    const txt = s.txt || {};
    if (!txt.id) return;
    if (txt.id === nodeId) {
      // Thấy được chính quảng bá của mình = chuỗi đăng ký → dò → phân giải → đọc TXT chạy thông.
      if (!thayChinhMinh) { thayChinhMinh = true; onLog?.("mDNS: đã thấy chính quảng bá của máy này — dò LAN hoạt động."); }
      return;
    }
    const ipv4 = (s.addresses || []).find((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a));
    if (!ipv4) return;
    peers.set(txt.id, { id: txt.id, name: txt.name || "?", fp: txt.fp || "", pub: txt.pub || "", host: ipv4, port: s.port, _sname: s.name });
    bao();
  });
  zc.on("remove", (sname) => {
    for (const [id, p] of peers) if (p._sname === sname) { peers.delete(id); bao(); break; }
  });
  zc.on("error", (e) => onLog?.(`mDNS lỗi: ${e?.message || e}`));

  const quangBa = (thongTin) => {
    zc.publishService(LOAI, "tcp", "local.", tenDichVu, port,
      { id: nodeId, name: thongTin.name, fp: thongTin.fp, pub: thongTin.pub });
  };
  quangBa({ name, fp, pub });
  zc.scan(LOAI, "tcp", "local.");
  onLog?.(`mDNS: quảng bá _sentinell._tcp cổng ${port} và bắt đầu dò.`);

  return {
    capNhat(thongTin) {
      try { zc.unpublishService(tenDichVu); } catch { /* */ }
      quangBa(thongTin);
    },
    dung() {
      try { zc.unpublishService(tenDichVu); } catch { /* */ }
      try { zc.stop(); } catch { /* */ }
      try { zc.removeDeviceListeners(); } catch { /* */ }
      peers.clear();
    },
  };
}
