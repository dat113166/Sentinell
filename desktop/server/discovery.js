// Tìm thiết bị trên LAN bằng mDNS/DNS-SD (bonjour-service) — port từ discovery.py.
// Cùng loại dịch vụ `_sentinell._tcp` và cùng khóa TXT (id, name, fp, pub) với bản Python,
// nên node Python và node Electron nhìn thấy nhau.
import os from "node:os";
import { Bonjour } from "bonjour-service";
import { tenDuongTrucTiep } from "./mangcuc.js";

export const SERVICE_TYPE = "sentinell"; // -> _sentinell._tcp.local

// Card mạng ẢO (VirtualBox, VMware, WSL, Hyper-V, Docker, VPN…) cũng có IPv4 không
// "internal", và `os.networkInterfaces()` không hứa hẹn thứ tự nào cả. Lấy bừa cái đầu
// tiên là có ngày mã QR mang địa chỉ mà điện thoại không với tới được → trang cứ xoay
// mãi không tải. Vì thế phải CHẤM ĐIỂM rồi chọn, và trả về cả danh sách để người dùng
// tự đổi nếu máy có nhiều card.
const TEN_CARD_AO = /virtual|vmware|vbox|virtualbox|hyper-?v|wsl|docker|loopback|tap|tun|vpn|tailscale|zerotier|bluetooth|npcap/i;

function diemCard(ten, dia, mask) {
  let d = 0;
  // Đường NỐI TRỰC TIẾP (điểm phát sóng của máy tính, hoặc của điện thoại qua WiFi/
  // cáp USB/Bluetooth) phải thắng áp đảo mọi mạng chung: đó là đường an toàn duy nhất
  // cho chế độ web. Trước đây nó chỉ hơn vài điểm — gặp mạng 192.168.x là thua ngay,
  // và mã QR mặc định trỏ vào đúng đường kém an toàn hơn.
  const trucTiep = !!tenDuongTrucTiep(dia, mask);
  if (trucTiep) d += 60;
  // Card "ảo" bị phạt nặng — TRỪ KHI nó đang mang địa chỉ của một đường nối trực tiếp.
  // iPhone chia sẻ qua Bluetooth hiện ra dưới tên "Bluetooth Network Connection" nhưng
  // mang 172.20.10.x/28: đó là đường thật và là đường AN TOÀN NHẤT, phạt nó là sai.
  if (!trucTiep && TEN_CARD_AO.test(ten)) d -= 100;
  if (/^wi-?fi|wlan|wireless/i.test(ten)) d += 30;  // hotspot điện thoại hầu như luôn là Wi-Fi
  if (/ethernet|eth\d|lan/i.test(ten)) d += 20;
  if (/^169\.254\./.test(dia)) d -= 80;             // link-local: chưa xin được DHCP
  else if (/^192\.168\./.test(dia)) d += 12;
  else if (/^172\.(1[6-9]|2\d|3[01])\./.test(dia)) d += 10;  // gồm 172.20.10.x của hotspot iPhone
  else if (/^10\./.test(dia)) d += 8;
  return d;
}

/** Mọi địa chỉ IPv4 dùng được, tốt nhất đứng đầu. */
export function localIps() {
  const ds = [];
  for (const [ten, ifaces] of Object.entries(os.networkInterfaces())) {
    for (const i of ifaces || []) {
      if (i.family !== "IPv4" || i.internal) continue;
      // netmask cần cho việc chỉ phục vụ /join đúng mạng con đã chọn (xem mangcuc.js)
      ds.push({ ip: i.address, iface: ten, netmask: i.netmask, diem: diemCard(ten, i.address, i.netmask) });
    }
  }
  ds.sort((a, b) => b.diem - a.diem);
  return ds;
}

export function localIp() {
  const ds = localIps();
  return ds.length ? ds[0].ip : "127.0.0.1";
}

export class Discovery {
  constructor({ nodeId, name, fp, pub, port, onChange }) {
    this.nodeId = nodeId;
    this.name = name;
    this.fp = fp;
    this.pub = pub;
    this.port = port;
    this.onChange = onChange;
    this.peers = new Map(); // id -> {id,name,fp,pub,host,port,_sname}
    this.bonjour = null;
    this.service = null;
    this.browser = null;
  }

  _txt() {
    const t = { id: this.nodeId, name: this.name, fp: this.fp };
    if (this.pub) t.pub = this.pub;
    return t;
  }

  start() {
    this.bonjour = new Bonjour();
    this._publish();
    this.browser = this.bonjour.find({ type: SERVICE_TYPE }, (s) => this._onUp(s));
    this.browser.on("down", (s) => this._onDown(s));
  }

  _publish() {
    this.service = this.bonjour.publish({
      name: `sentinell-${this.nodeId.slice(0, 10)}`,
      type: SERVICE_TYPE,
      port: this.port,
      txt: this._txt(),
    });
  }

  async updateProps({ name, fp, pub }) {
    if (name !== undefined) this.name = name;
    if (fp !== undefined) this.fp = fp;
    if (pub !== undefined) this.pub = pub;
    if (!this.bonjour) return;
    await new Promise((res) => (this.service ? this.service.stop(res) : res()));
    this._publish();
  }

  _onUp(s) {
    const txt = s.txt || {};
    const id = txt.id;
    if (!id || id === this.nodeId) return;
    const ipv4 = (s.addresses || []).find((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a))
      || (s.referer && s.referer.address);
    if (!ipv4) return;
    this.peers.set(id, {
      id, name: txt.name || "?", fp: txt.fp || "", pub: txt.pub || "",
      host: ipv4, port: s.port, _sname: s.name,
    });
    this._notify();
  }

  _onDown(s) {
    for (const [id, p] of this.peers) {
      if (p._sname === s.name) { this.peers.delete(id); this._notify(); break; }
    }
  }

  _notify() {
    const list = [...this.peers.values()].map(({ _sname, ...p }) => p);
    this.onChange(list);
  }

  async stop() {
    try {
      if (this.browser) this.browser.stop();
      await new Promise((res) => (this.service ? this.service.stop(res) : res()));
      if (this.bonjour) this.bonjour.destroy();
    } catch { /* bỏ qua */ }
  }
}
