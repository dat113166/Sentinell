// Điện thoại NGHE kết nối: TCP của react-native-tcp-socket + WebSocket tự viết (wsproto.js).
// Nhờ đây mà máy tính gọi được sang điện thoại, và hai điện thoại nhắn thẳng cho nhau.
//
// Mô-đun native chỉ có trong bản build thật (development/release build). Chạy trong Expo Go
// thì không có — khi đó trả về null và app vẫn dùng được chiều GỌI ĐI như trước.
import { NativeModules } from "react-native";
import { WsConn } from "./wsproto";

export const CONG_MAC_DINH = 8000;
const SO_CONG_THU = 10;
const LOI_TRINH_DUYET =
  "Đây là cổng nhắn tin của app Sentinell trên điện thoại, không phải trang web.\n"
  + "Hãy kết nối bằng app Sentinell (máy tính hoặc điện thoại), đừng mở bằng trình duyệt.\n";

export function coTheNghe() {
  return !!NativeModules.TcpSockets;
}

/**
 * Mở máy chủ ở cổng đầu tiên còn trống trong [cong, cong+9].
 * onConnection(conn) chỉ được gọi SAU khi bắt tay WebSocket xong.
 * Trả về { port, close() } hoặc null nếu không nghe được.
 */
export async function moMayChu({ cong = CONG_MAC_DINH, onConnection, onLog }) {
  if (!coTheNghe()) return null;
  // Thư viện vừa `export default` vừa gán đè `module.exports` ⇒ qua Metro thì `.default` mất.
  const mod = require("react-native-tcp-socket");
  const TcpSocket = mod.default || mod;
  for (let p = cong; p < cong + SO_CONG_THU; p++) {
    const srv = await thuNghe(TcpSocket, p, (sock) => {
      const conn = new WsConn(sock, { refusal: LOI_TRINH_DUYET });
      conn.onopen = () => onConnection(conn);
    });
    if (srv) {
      onLog?.(`Đang nghe kết nối ở cổng ${p}.`);
      return {
        port: p,
        close: () => new Promise((res) => { try { srv.close(() => res()); } catch { res(); } }),
      };
    }
    onLog?.(`Cổng ${p} đang bận — thử cổng kế.`);
  }
  return null;
}

function thuNghe(TcpSocket, port, onSocket) {
  return new Promise((res) => {
    let xong = false;
    const srv = TcpSocket.createServer({ noDelay: true, keepAlive: true }, onSocket);
    srv.once("error", () => { if (!xong) { xong = true; try { srv.close(); } catch { /* */ } res(null); } });
    srv.listen({ port, host: "0.0.0.0", reuseAddress: true }, () => { if (!xong) { xong = true; res(srv); } });
  });
}
