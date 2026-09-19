// Màn hình chính: danh tính của điện thoại (QR khóa để máy khác quét), quét QR để kết nối,
// thiết bị trong LAN, danh bạ đã ghim, kết nối thủ công, quản lý khóa và mật khẩu.
import React, { useState } from "react";
import { Platform, ScrollView, TextInput, View, Text, Alert, Switch } from "react-native";
import QRCode from "react-native-qrcode-svg";
import { fingerprint } from "@sentinell/core";
import { Btn, Card, H2, Muted, Mono, Pill, s } from "../ui";
import PasswordModal from "./PasswordModal";
import { C } from "../theme";

export default function HomeScreen({
  identity, pairCode, contacts, onScan, onConnect, onRename, onRotate, notice,
  nghe, lanPeers = [], strict, nhatKyMay = [], coMatKhau, onStrict, onAccount, onLock,
}) {
  const [name, setName] = useState(identity.name);
  const [addr, setAddr] = useState("");
  const [hopMk, setHopMk] = useState(null);   // "tao" | "doi" | "bo"
  const myFp = fingerprint(identity.pub);
  // Điện thoại giờ NGHE được → QR mang luôn địa chỉ: máy tính quét là gọi sang được ngay.
  const keyPayload = JSON.stringify({
    k: identity.pub, n: identity.name, fp: myFp, pc: pairCode,
    ...(nghe?.ip ? { h: nghe.ip, p: nghe.port } : {}),
  });
  const ghimTheoPub = new Map(contacts.map((c) => [c.pub, c]));

  function manualConnect() {
    const m = addr.trim().match(/^(\d+\.\d+\.\d+\.\d+):(\d+)$/);
    if (!m) { Alert.alert("Địa chỉ không hợp lệ", "Nhập dạng 192.168.1.10:8000"); return; }
    onConnect({ host: m[1], port: Number(m[2]), expectPub: null, peerName: addr.trim() });
  }

  return (
    <ScrollView
      style={{ flex: 1, backgroundColor: C.bg }}
      contentContainerStyle={{ padding: 16, paddingBottom: 40 }}
      // Mặc định "never": chạm nút lúc bàn phím đang mở chỉ để ẨN bàn phím, nút không nhận
      // (hộp mật khẩu nằm trong cây này — đã gặp: bấm "Lưu" lần đầu không có gì xảy ra).
      keyboardShouldPersistTaps="handled"
    >
      <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 14 }}>
        <Text style={{ color: C.fg, fontSize: 22, fontWeight: "700" }}>
          <Text style={{ color: C.accent }}>🛡️</Text> Sentinell
        </Text>
        <View style={{ flex: 1 }} />
        <Pill text={Platform.OS} />
      </View>

      {notice ? (
        <Card style={{ borderColor: notice.bad ? C.danger : C.border }}>
          <Muted style={{ color: notice.bad ? C.danger : C.dim }}>{notice.text}</Muted>
        </Card>
      ) : null}

      <Card>
        <H2>📷 Kết nối bằng QR</H2>
        <Muted>
          Trên máy tính mở Sentinell → <Text style={{ color: C.fg }}>🔑 Khóa &amp; QR của tôi</Text> → mục
          “Mời điện thoại”. Quét mã đó: điện thoại sẽ tự ghim khóa máy tính (trao đổi khóa ngoài kênh
          mạng) rồi bắt tay mã hóa.
        </Muted>
        <Btn title="Mở camera quét QR" onPress={onScan} style={{ marginTop: 12 }} />
      </Card>

      <Card>
        <H2>📱 Khóa của điện thoại này</H2>
        <Muted>
          {nghe?.ip
            ? "Cho máy khác quét mã này: họ ghim khóa của bạn và gọi sang luôn (xác minh hai chiều)."
            : "Cho máy tính quét mã này để ghim khóa của bạn (xác minh hai chiều)."}
        </Muted>
        <View style={{ alignItems: "center", marginVertical: 14, backgroundColor: "#fff", padding: 12, borderRadius: 10, alignSelf: "center" }}>
          <QRCode value={keyPayload} size={180} backgroundColor="#fff" color="#000" />
        </View>
        <Mono>vân tay: {myFp}</Mono>
        <Mono>mã ghép đôi: {pairCode}</Mono>
        <View style={{ flexDirection: "row", gap: 8, marginTop: 12, alignItems: "center" }}>
          <TextInput
            value={name}
            onChangeText={setName}
            placeholder="Tên hiển thị"
            placeholderTextColor={C.dim}
            style={inputStyle}
          />
          <Btn title="Lưu" kind="ghost" onPress={() => onRename(name)} />
        </View>
        <Btn
          title="🔄 Xoay khóa (đổi khóa mới)"
          kind="ghost"
          style={{ marginTop: 10 }}
          onPress={() =>
            Alert.alert("Xoay khóa?", "Sẽ tạo danh tính mới; các liên hệ phải quét lại QR của bạn.", [
              { text: "Hủy", style: "cancel" },
              { text: "Xoay khóa", style: "destructive", onPress: onRotate },
            ])
          }
        />
      </Card>

      <Card>
        <H2>📡 Trong mạng LAN</H2>
        {nghe ? (
          <View style={{ flexDirection: "row", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <Pill kind="ok" text="đang nghe" />
            <Mono>{nghe.ip ? `${nghe.ip}:${nghe.port}` : `cổng ${nghe.port}`}</Mono>
          </View>
        ) : (
          <Muted>Chưa nghe kết nối — máy khác chưa gọi vào được (bản Expo Go không có chiều này).</Muted>
        )}
        <View style={{ flexDirection: "row", alignItems: "center", marginTop: 10 }}>
          <View style={{ flex: 1 }}>
            <Text style={{ color: C.fg, fontWeight: "600" }}>Chế độ chặt</Text>
            <Muted>Chỉ nhận kết nối từ liên hệ đã ghim khóa; thiết bị lạ bị từ chối thẳng, không hỏi.</Muted>
          </View>
          <Switch value={!!strict} onValueChange={onStrict} thumbColor={strict ? C.accent : C.dim} trackColor={{ true: "#1c5c44", false: C.border }} />
        </View>
        {lanPeers.length === 0 ? (
          <Muted style={{ marginTop: 10 }}>{nghe ? "Chưa thấy thiết bị Sentinell nào khác trong mạng này." : ""}</Muted>
        ) : (
          lanPeers.map((p) => {
            // Khóa trong TXT mDNS là do máy kia tự khai — chỉ dùng làm khóa ghim khi nó TRÙNG
            // một liên hệ đã ghim qua QR; không thì kết nối như máy lạ và đối chiếu safety number.
            const ghim = ghimTheoPub.get(p.pub);
            return (
              <View key={p.id} style={rowStyle}>
                <View style={{ flex: 1 }}>
                  <Text style={{ color: C.fg, fontWeight: "600" }}>{ghim ? ghim.name : p.name}</Text>
                  <Mono>{p.host}:{p.port} · {p.fp}</Mono>
                  <View style={{ marginTop: 4 }}><Pill kind={ghim ? "ok" : "warn"} text={ghim ? "khóa đã ghim" : "chưa xác minh"} /></View>
                </View>
                <Btn title="Kết nối" onPress={() => onConnect({ host: p.host, port: p.port, expectPub: ghim ? ghim.pub : null, peerName: ghim ? ghim.name : p.name })} />
              </View>
            );
          })
        )}
        {nhatKyMay.length ? (
          <View style={{ marginTop: 10 }}>
            {nhatKyMay.slice(-3).map((t, i) => <Mono key={i} style={{ fontSize: 11 }}>› {t}</Mono>)}
          </View>
        ) : null}
      </Card>

      <Card>
        <H2>🔗 Đã ghim qua QR</H2>
        {contacts.length === 0 ? (
          <Muted>Chưa ghim khóa nào. Quét QR của máy tính để ghim.</Muted>
        ) : (
          contacts.map((c) => (
            <View key={c.fingerprint} style={rowStyle}>
              <View style={{ flex: 1 }}>
                <Text style={{ color: C.fg, fontWeight: "600" }}>{c.name}</Text>
                <Mono>{c.fingerprint}</Mono>
                {c.host ? <Mono>{c.host}:{c.port}</Mono> : null}
              </View>
              {c.host ? (
                <Btn
                  title="Kết nối"
                  onPress={() => onConnect({ host: c.host, port: c.port, expectPub: c.pub, peerName: c.name })}
                />
              ) : (
                <Pill text="cần quét lại để có địa chỉ" />
              )}
            </View>
          ))
        )}
      </Card>

      <Card>
        <H2>⌨️ Kết nối thủ công</H2>
        <Muted>Dùng khi mạng chặn QR/đa hướng. Nhập IP:cổng hiện trên máy tính.</Muted>
        <View style={{ flexDirection: "row", gap: 8, marginTop: 10, alignItems: "center" }}>
          <TextInput
            value={addr}
            onChangeText={setAddr}
            placeholder="192.168.1.10:8000"
            placeholderTextColor={C.dim}
            autoCapitalize="none"
            keyboardType="numbers-and-punctuation"
            style={inputStyle}
          />
          <Btn title="Nối" kind="ghost" onPress={manualConnect} />
        </View>
        <Muted style={{ marginTop: 8 }}>
          Kết nối kiểu này chưa xác minh khóa — hãy đối chiếu safety number sau khi vào phòng.
        </Muted>
      </Card>

      {coMatKhau ? (
        <Card>
          <H2>🔐 Mật khẩu</H2>
          {identity.account ? (
            <>
              <Muted>
                Khóa bí mật đang được bọc bằng mật khẩu (scrypt N=2^{Math.log2(identity.account.N)} → AES-256-GCM).
                Rời app quá 5 phút sẽ tự khóa.
              </Muted>
              <Btn title="🔒 Khóa ngay" style={{ marginTop: 10 }} onPress={onLock} />
              <View style={{ flexDirection: "row", gap: 8, marginTop: 8 }}>
                <Btn title="Đổi mật khẩu" kind="ghost" style={{ flex: 1 }} onPress={() => setHopMk("doi")} />
                <Btn title="Bỏ mật khẩu" kind="ghost" style={{ flex: 1 }} onPress={() => setHopMk("bo")} />
              </View>
            </>
          ) : (
            <>
              <Muted>
                Chưa đặt mật khẩu: khóa chỉ được Keystore của Android bảo vệ — ai mở được máy là mở được app.
              </Muted>
              <Btn title="Đặt mật khẩu" style={{ marginTop: 10 }} onPress={() => setHopMk("tao")} />
            </>
          )}
        </Card>
      ) : null}

      <PasswordModal
        mode={hopMk}
        onClose={() => setHopMk(null)}
        onSubmit={(mk, mkMoi, onProgress) => onAccount(hopMk, mk, mkMoi, onProgress)}
      />
    </ScrollView>
  );
}

const inputStyle = {
  flex: 1,
  backgroundColor: C.soft,
  borderColor: C.border,
  borderWidth: 1,
  borderRadius: 8,
  color: C.fg,
  paddingHorizontal: 12,
  paddingVertical: 10,
};

const rowStyle = {
  flexDirection: "row",
  alignItems: "center",
  gap: 10,
  backgroundColor: C.soft,
  borderColor: C.border,
  borderWidth: 1,
  borderRadius: 10,
  padding: 10,
  marginTop: 8,
};
