// Sentinell mobile — app nhắn tin bảo mật đầu cuối trên Android/iOS.
// Dùng CHUNG lõi giao thức @sentinell/core với bản desktop (Electron) và trang web /join,
// nên điện thoại là một "đầu cuối" thật: khóa và việc mã hóa/giải mã nằm trên máy này.
//
// Bản build Android (không phải Expo Go) còn làm được ba việc của một "node" đầy đủ:
//   • NGHE kết nối (peerserver.js) → máy tính và điện thoại khác gọi vào được;
//   • tìm máy trong LAN bằng mDNS (discovery.js);
//   • khóa bí mật được bọc bằng mật khẩu (storage.js) — chỉ bật trên Android.
import React, { useCallback, useEffect, useRef, useState } from "react";
import { StatusBar, View, ActivityIndicator, Alert, AppState, Platform } from "react-native";
// SafeAreaView của react-native chỉ chạy trên iOS. Android 15+ bắt app vẽ tràn dưới thanh trạng
// thái và thanh điều hướng (edge-to-edge) → phải lấy khoảng thụt thật từ thư viện này.
import { SafeAreaProvider, SafeAreaView } from "react-native-safe-area-context";
import * as Network from "expo-network";
import { fingerprint, newPairCode } from "@sentinell/core";

import * as store from "./src/storage";
import { PeerLink, tuChoiBan } from "./src/transport";
import { moMayChu, coTheNghe } from "./src/peerserver";
import { batDauTim, coTheTim } from "./src/discovery";
import HomeScreen from "./src/screens/HomeScreen";
import ScannerScreen from "./src/screens/ScannerScreen";
import ChatScreen from "./src/screens/ChatScreen";
import LockScreen from "./src/screens/LockScreen";
import ApprovalModal from "./src/screens/ApprovalModal";
import { C } from "./src/theme";

export const CO_MAT_KHAU = Platform.OS === "android";   // đăng nhập chỉ áp dụng cho app Android
const TU_KHOA_SAU_MS = 5 * 60 * 1000;                     // rời app quá 5 phút thì khóa lại

export default function App() {
  const [ready, setReady] = useState(false);
  const [identity, setIdentity] = useState(null);         // đầy đủ (đã mở khóa) hoặc { locked: true, … }
  const [contacts, setContacts] = useState([]);
  const [screen, setScreen] = useState("home");           // home | scan | chat
  const [conn, setConn] = useState(null);
  const [messages, setMessages] = useState([]);
  const [logs, setLogs] = useState([]);
  const [notice, setNotice] = useState(null);
  const [pairCodeMine, setPairCodeMine] = useState(() => newPairCode()); // mã trong QR của điện thoại này
  const [nghe, setNghe] = useState(null);                 // { port, ip } khi đang nghe
  const [lanPeers, setLanPeers] = useState([]);
  const [approval, setApproval] = useState(null);
  const [strict, setStrictState] = useState(false);
  const [nhatKyMay, setNhatKyMay] = useState([]);         // nhật ký của máy chủ/mDNS (không phải của phiên)

  const client = useRef(null);
  const identityRef = useRef(null);
  const pairCodeRef = useRef(pairCodeMine);
  const strictRef = useRef(false);
  const nodeIdRef = useRef(null);
  const mayChu = useRef(null);
  const timLan = useRef(null);
  const roiAppLuc = useRef(null);

  useEffect(() => { identityRef.current = identity; }, [identity]);
  useEffect(() => { pairCodeRef.current = pairCodeMine; }, [pairCodeMine]);
  useEffect(() => { strictRef.current = strict; }, [strict]);

  const ghiMay = useCallback((t) => {
    console.log("[sentinell] " + t);
    setNhatKyMay((l) => [...l.slice(-30), t]);
  }, []);

  const flash = useCallback((text, bad = false) => {
    setNotice({ text, bad });
    setTimeout(() => setNotice(null), 6000);
  }, []);

  const refreshContacts = useCallback(async () => {
    setContacts(await store.listContacts());
  }, []);

  // ---- khởi động: mở kho cục bộ + nạp/sinh danh tính ----
  useEffect(() => {
    (async () => {
      await store.init();
      nodeIdRef.current = await store.nodeId();
      const st = await store.getStrict();
      setStrictState(st); strictRef.current = st;
      const id = await store.loadIdentity();
      setIdentity(id);
      identityRef.current = id;
      if (!id.locked) setContacts(await store.listContacts());
      setReady(true);
    })().catch((e) => {
      Alert.alert("Không khởi động được", String(e?.message || e));
      setReady(true);
    });
    return () => client.current?.close();
  }, []);

  // ---------------------------------------------------------------- một phiên (cả hai chiều)
  /** Mọi phiên — gọi đi hay được gọi vào — đi qua đúng MỘT bộ xử lý, để lưu lịch sử,
   *  ghim hai chiều và thông báo ngắt kết nối giống hệt nhau. */
  const taoPhien = useCallback((extra) => {
    client.current?.close();
    setMessages([]);
    setLogs([]);
    const c = new PeerLink({
      identity: identityRef.current,
      activePairCode: pairCodeRef.current,  // mã trong QR của tôi → để bên kia chứng minh đã quét
      listenPort: mayChu.current?.port || null,
      lookupContact: (pub) => store.contactByPub(pub),
      strict: strictRef.current,
      ...extra,
      onLog: (step, detail) => setLogs((l) => [...l.slice(-120), { step, detail }]),
      onNotice: (text, bad) => flash(text, bad),
      onApproval: (req) => setApproval(req),
      onConnected: async (info) => {
        setConn(info);
        setScreen("chat");
        // nạp lịch sử đã lưu cục bộ (đã mã hóa at-rest) của đúng peer này
        setMessages(await store.loadHistory(identityRef.current, info.peerPub));
        // GHIM HAI CHIỀU (như desktop): bên kia chứng minh đã quét mã của tôi, hoặc khóa đã
        // khớp khóa ghim từ trước → lưu/cập nhật danh bạ kèm địa chỉ để lần sau gọi lại được.
        if (info.peerProvedPair || info.trusted) {
          await store.pinContact(info.peerPub, info.peerName, info.host, info.port);
          refreshContacts();
          if (info.peerProvedPair) {
            flash(`Đã ghép đôi với "${info.peerName}" — từ nay hai bên nhắn lại được mà không cần quét lại.`);
            setPairCodeMine(newPairCode());   // mã dùng một lần: đổi ngay sau khi ghép xong
          }
        }
      },
      onMessage: async (body) => {
        const peerPub = c.session?.peer?.id_pub;
        // Lưu lịch sử KHÔNG kèm base64 của ảnh để kho cục bộ không phình to;
        // ảnh vẫn hiển thị trong phiên hiện tại qua dataUri giữ trong bộ nhớ.
        const { dataUri, ...slim } = body;
        const ts = peerPub ? await store.saveMessage(identityRef.current, peerPub, "in", slim) : Date.now() / 1000;
        setMessages((m) => [...m, { direction: "in", ts, body }]);
      },
      onDisconnected: (reason, daVao) => {
        if (client.current === c) client.current = null;
        setConn(null);
        setScreen((s) => (s === "chat" ? "home" : s));
        if (daVao || c.role === "I") flash(reason, true);
      },
    });
    client.current = c;
    return c;
  }, [flash, refreshContacts]);

  const connect = useCallback(({ host, port, expectPub, peerName, pairCode = null }) => {
    const c = taoPhien({ expectPub, pairCode });
    c.connect(host, port);
    ghiMay(`Gọi tới ${peerName || ""} ${host}:${port}`);
  }, [taoPhien, ghiMay]);

  // Có người gọi vào máy chủ của điện thoại.
  const onKetNoiDen = useCallback((ws) => {
    if (identityRef.current?.locked) { tuChoiBan(ws); return; }
    // Đang trò chuyện thật (hoặc đang chờ duyệt) thì từ chối người mới — y như desktop.
    if (client.current && client.current.busy) {
      tuChoiBan(ws);
      flash("📵 Một thiết bị vừa xin kết nối nhưng bị từ chối vì bạn đang bận với phiên khác.");
      return;
    }
    ghiMay(`Kết nối đến từ ${ws.remoteAddress || "?"}`);
    taoPhien({}).accept(ws);
  }, [taoPhien, flash, ghiMay]);
  // Máy chủ giữ MỘT callback suốt đời chạy → đi qua ref để luôn gọi bản mới nhất.
  const onKetNoiDenRef = useRef(onKetNoiDen);
  useEffect(() => { onKetNoiDenRef.current = onKetNoiDen; }, [onKetNoiDen]);

  // ---------------------------------------------------------------- nghe + dò LAN
  const dungMang = useCallback(async () => {
    timLan.current?.dung(); timLan.current = null;
    const m = mayChu.current; mayChu.current = null;
    if (m) await m.close();
    setNghe(null);
    setLanPeers([]);
  }, []);

  useEffect(() => {
    if (!ready || !identity || identity.locked) return undefined;
    if (mayChu.current) return undefined;
    let huy = false;
    (async () => {
      if (!coTheNghe()) { ghiMay("Bản này không có mô-đun TCP (đang chạy Expo Go?) — chỉ gọi đi được."); return; }
      const m = await moMayChu({ onConnection: (ws) => onKetNoiDenRef.current(ws), onLog: ghiMay });
      if (huy) { m?.close(); return; }
      if (!m) { ghiMay("Không mở được cổng nào để nghe."); return; }
      mayChu.current = m;
      let ip = null;
      try { ip = await Network.getIpAddressAsync(); } catch { /* */ }
      if (ip === "0.0.0.0") ip = null;
      setNghe({ port: m.port, ip });
      if (coTheTim()) {
        const id = identityRef.current;
        timLan.current = batDauTim({
          nodeId: nodeIdRef.current, name: id.name, fp: fingerprint(id.pub), pub: id.pub, port: m.port,
          onPeers: setLanPeers, onLog: ghiMay,
        });
      } else ghiMay("Bản này không có mô-đun mDNS — không tự tìm máy trong LAN được.");
    })().catch((e) => ghiMay(`Lỗi khi mở máy chủ: ${e?.message || e}`));
    return () => { huy = true; };
  }, [ready, identity?.locked, ghiMay]);

  // Đổi tên/xoay khóa → quảng bá lại để máy khác thấy đúng.
  useEffect(() => {
    if (identity && !identity.locked && timLan.current) {
      timLan.current.capNhat({ name: identity.name, fp: fingerprint(identity.pub), pub: identity.pub });
    }
  }, [identity?.name, identity?.pub]);

  // ---------------------------------------------------------------- khóa / mở khóa
  const khoaLai = useCallback(async (lyDo) => {
    if (!identityRef.current?.account) return;
    client.current?.close();
    client.current = null;
    await dungMang();
    store.lock();
    const locked = await store.loadIdentity();
    setIdentity(locked);
    setConn(null); setMessages([]); setLogs([]); setContacts([]); setApproval(null);
    setScreen("home");
    if (lyDo) flash(lyDo);
  }, [dungMang, flash]);

  const moKhoa = useCallback(async (matKhau, onProgress) => {
    const { id, ms } = await store.unlock(identityRef.current, matKhau, onProgress);
    setIdentity(id);
    identityRef.current = id;
    setContacts(await store.listContacts());
    ghiMay(`Mở khóa: dẫn khóa scrypt N=2^${Math.log2(id.account.N)} mất ${ms} ms.`);
  }, [ghiMay]);

  // Rời app lâu thì tự khóa: ai nhặt được máy đang mở cũng không đọc được tin.
  useEffect(() => {
    const sub = AppState.addEventListener("change", (s) => {
      if (s === "background") roiAppLuc.current = Date.now();
      else if (s === "active" && roiAppLuc.current) {
        const lau = Date.now() - roiAppLuc.current;
        roiAppLuc.current = null;
        if (lau > TU_KHOA_SAU_MS && identityRef.current?.account && !identityRef.current.locked) {
          khoaLai("Đã tự khóa vì bạn rời app hơn 5 phút.");
        }
      }
    });
    return () => sub.remove();
  }, [khoaLai]);

  const taiKhoan = useCallback(async (viec, matKhau, matKhauMoi, onProgress) => {
    const id = identityRef.current;
    if (viec === "tao") {
      const { id: next, thongKe } = await store.createAccount(id, matKhau, onProgress);
      setIdentity(next);
      ghiMay(`Đặt mật khẩu: scrypt N=2^${Math.log2(thongKe.N)} (ước ${thongKe.uocTinhMs} ms, thực ${thongKe.thucTeMs} ms).`);
      flash("Đã đặt mật khẩu. Lần mở app sau sẽ phải nhập mật khẩu.");
    } else if (viec === "doi") {
      setIdentity(await store.changePassword(id, matKhau, matKhauMoi, onProgress));
      flash("Đã đổi mật khẩu.");
    } else if (viec === "bo") {
      setIdentity(await store.removeAccount(id, matKhau, onProgress));
      flash("Đã bỏ mật khẩu. Khóa quay về chỉ được Keystore của Android bảo vệ.");
    }
  }, [flash, ghiMay]);

  const doiCheDoChat = useCallback(async (v) => {
    await store.setStrict(v);
    setStrictState(v);
    flash(v ? "Chế độ chặt: chỉ nhận kết nối từ liên hệ đã ghim khóa." : "Đã tắt chế độ chặt: thiết bị lạ gọi vào sẽ được hỏi.");
  }, [flash]);

  // ---------------------------------------------------------------- quét QR
  const onScanResult = useCallback(async (r) => {
    setScreen("home");
    if (r.kind === "invite" || (r.kind === "key" && r.host && r.port)) {
      if (r.pub) {
        await store.pinContact(r.pub, r.name, r.host, r.port);
        await refreshContacts();
        flash(`Đã ghim khóa của ${r.name || "thiết bị"} (${fingerprint(r.pub).slice(0, 8)}…) từ QR.`);
      }
      connect({ host: r.host, port: r.port, expectPub: r.pub || null, peerName: r.name, pairCode: r.pairCode });
      return;
    }
    if (r.kind === "key") {
      await store.pinContact(r.pub, r.name);
      await refreshContacts();
      flash(`Đã ghim khóa ${fingerprint(r.pub).slice(0, 8)}…. Mã này không kèm địa chỉ — hãy bấm Kết nối ở thiết bị kia.`);
      return;
    }
    if (r.kind === "address") {
      connect({ host: r.host, port: r.port, expectPub: null, peerName: `${r.host}:${r.port}` });
      return;
    }
    flash("Mã QR không phải của Sentinell.", true);
  }, [connect, flash, refreshContacts]);

  // ---------------------------------------------------------------- gửi
  const send = useCallback(async (text) => {
    const body = client.current?.sendText(text);
    if (!body) return;
    const peerPub = client.current.session.peer.id_pub;
    const ts = await store.saveMessage(identityRef.current, peerPub, "out", body);
    setMessages((m) => [...m, { direction: "out", ts, body }]);
  }, []);

  const sendImage = useCallback(async ({ base64, name, mime }) => {
    const body = client.current?.sendFile({ base64, name, mime });
    if (!body) return;
    const peerPub = client.current.session.peer.id_pub;
    // không lưu ảnh base64 vào lịch sử để tránh phình kho; chỉ lưu thông tin tệp
    const ts = await store.saveMessage(identityRef.current, peerPub, "out",
      { type: "file", name: body.name, mime: body.mime, size: body.size, integrity: true });
    setMessages((m) => [...m, { direction: "out", ts, body }]);
  }, []);

  // ---------------------------------------------------------------- khóa
  const rename = useCallback(async (name) => {
    const next = await store.setName(identityRef.current, name);
    setIdentity(next);
    flash("Đã đổi tên hiển thị.");
  }, [flash]);

  const rotate = useCallback(async () => {
    const next = await store.rotateIdentity(identityRef.current);
    setIdentity(next);
    flash("Đã xoay khóa. Liên hệ cần quét lại QR của bạn.");
  }, [flash]);

  // ---------------------------------------------------------------- render
  if (!ready || !identity) {
    return (
      <View style={{ flex: 1, backgroundColor: C.bg, alignItems: "center", justifyContent: "center" }}>
        <StatusBar barStyle="light-content" />
        <ActivityIndicator color={C.accent} />
      </View>
    );
  }

  // Màn quét để camera tràn cả màn hình; ScannerScreen tự thụt phần chữ/nút theo insets.
  return (
    <SafeAreaProvider>
    <SafeAreaView style={{ flex: 1, backgroundColor: C.bg }} edges={screen === "scan" && !identity.locked ? [] : ["top", "bottom", "left", "right"]}>
      <StatusBar barStyle="light-content" />
      {identity.locked ? (
        <LockScreen name={identity.name} fp={fingerprint(identity.pub)} onUnlock={moKhoa} notice={notice} />
      ) : screen === "scan" ? (
        <ScannerScreen onResult={onScanResult} onCancel={() => setScreen("home")} />
      ) : screen === "chat" && conn ? (
        <ChatScreen
          conn={conn}
          messages={messages}
          logs={logs}
          onSend={send}
          onSendImage={sendImage}
          onLeave={() => { client.current?.close(); setScreen("home"); setConn(null); }}
        />
      ) : (
        <HomeScreen
          identity={identity}
          pairCode={pairCodeMine}
          contacts={contacts}
          notice={notice}
          nghe={nghe}
          lanPeers={lanPeers}
          strict={strict}
          nhatKyMay={nhatKyMay}
          coMatKhau={CO_MAT_KHAU}
          onScan={() => setScreen("scan")}
          onConnect={connect}
          onRename={rename}
          onRotate={rotate}
          onStrict={doiCheDoChat}
          onAccount={taiKhoan}
          onLock={() => khoaLai("Đã khóa. Nhập mật khẩu để mở lại.")}
        />
      )}
      <ApprovalModal
        req={approval}
        onAccept={() => client.current?.approve()}
        onReject={() => client.current?.reject(client.current?.pending?.msg, "Bạn đã từ chối.")}
      />
    </SafeAreaView>
    </SafeAreaProvider>
  );
}
