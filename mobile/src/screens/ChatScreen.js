// Phòng chat: tin nhắn đã mã hóa đầu cuối, gửi ảnh, safety number và nhật ký giao thức.
import React, { useRef, useState, useEffect } from "react";
import { View, Text, TextInput, ScrollView, Image, KeyboardAvoidingView, Platform } from "react-native";
import * as ImagePicker from "expo-image-picker";
import { Btn, Card, Muted, Mono, Pill, H2 } from "../ui";
import { C } from "../theme";

/** Bỏ dấu + hạ chữ thường — giống Storage.khongDau() bên desktop, để gõ "bao cao"
 *  vẫn tìm ra "báo cáo". */
function khongDau(s) {
  return String(s ?? "")
    .normalize("NFD").replace(/[̀-ͯ]/g, "")
    .replace(/đ/g, "d").replace(/Đ/g, "D")
    .toLowerCase();
}

export default function ChatScreen({ conn, messages, logs, onSend, onSendImage, onLeave }) {
  const [text, setText] = useState("");
  const [showSafety, setShowSafety] = useState(false);
  const [showLog, setShowLog] = useState(false);
  const [tim, setTim] = useState(null);      // null = chưa bật ô tìm; "" = đang bật mà chưa gõ
  const scroller = useRef(null);

  // Lịch sử đã được nạp sẵn vào `messages` khi kết nối, nên lọc ngay tại chỗ là đủ —
  // không phải hỏi lại kho (và cũng không giải mã lại lần nữa).
  const q = khongDau(tim || "").trim();
  const hienThi = q
    ? messages.filter((m) => khongDau(m.body?.type === "file" ? m.body?.name : m.body?.text).includes(q))
    : messages;

  useEffect(() => {
    if (q) return;                           // đang tìm thì đừng giật xuống cuối
    const t = setTimeout(() => scroller.current?.scrollToEnd({ animated: true }), 60);
    return () => clearTimeout(t);
  }, [messages.length, q]);

  async function pickImage() {
    const perm = await ImagePicker.requestMediaLibraryPermissionsAsync();
    if (!perm.granted) return;
    const res = await ImagePicker.launchImageLibraryAsync({ mediaTypes: ["images"], base64: true, quality: 0.7 });
    if (res.canceled || !res.assets?.length) return;
    const a = res.assets[0];
    onSendImage({ base64: a.base64, name: a.fileName || "anh.jpg", mime: a.mimeType || "image/jpeg" });
  }

  function send() {
    const t = text.trim();
    if (!t) return;
    onSend(t);
    setText("");
  }

  return (
    <KeyboardAvoidingView
      style={{ flex: 1, backgroundColor: C.bg }}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
      keyboardVerticalOffset={0}
    >
      <View style={{ padding: 14, borderBottomWidth: 1, borderBottomColor: C.border, flexDirection: "row", alignItems: "center", gap: 10 }}>
        <View style={{ flex: 1 }}>
          <Text style={{ color: C.fg, fontWeight: "700", fontSize: 16 }}>{conn.peerName}</Text>
          <Pill
            text={conn.trusted ? "đã xác minh qua QR ✓" : "chưa xác minh — so safety number"}
            kind={conn.trusted ? "ok" : "warn"}
          />
        </View>
        <Btn title="🔎" kind="ghost" onPress={() => setTim((v) => (v === null ? "" : null))} />
        <Btn title="ℹ️" kind="ghost" onPress={() => setShowSafety((v) => !v)} />
        <Btn title="Rời" kind="danger" onPress={onLeave} />
      </View>

      {tim !== null && (
        <View style={{ padding: 12, paddingBottom: 0 }}>
          <TextInput
            value={tim}
            onChangeText={setTim}
            autoFocus
            placeholder="Tìm trong cuộc trò chuyện này…"
            placeholderTextColor={C.dim}
            style={{ backgroundColor: C.soft, borderColor: C.border, borderWidth: 1, borderRadius: 10, color: C.fg, paddingHorizontal: 12, paddingVertical: 9 }}
          />
          {q ? (
            <Muted style={{ marginTop: 6 }}>
              {hienThi.length
                ? `${hienThi.length} tin khớp — chỉ tìm trong lịch sử đã lưu trên máy này.`
                : "Không có tin nào khớp."}
            </Muted>
          ) : null}
        </View>
      )}

      {showSafety && (
        <Card style={{ margin: 12, marginBottom: 0 }}>
          <H2>Safety number</H2>
          <Muted>Đọc dãy số này cho nhau — khớp nghĩa là không có kẻ đứng giữa.</Muted>
          <Text style={{ color: C.fg, marginTop: 8, letterSpacing: 1, lineHeight: 22, flexShrink: 1 }}>{conn.safety}</Text>
          <Btn title={showLog ? "Ẩn nhật ký giao thức" : "🔎 Nhật ký giao thức"} kind="ghost" style={{ marginTop: 10 }} onPress={() => setShowLog((v) => !v)} />
          {showLog && (
            <View style={{ marginTop: 8, backgroundColor: "#0a0f1e", borderRadius: 8, padding: 8, maxHeight: 200, overflow: "hidden" }}>
              <ScrollView nestedScrollEnabled>
                {logs.map((l, i) => (
                  <View key={i} style={{ flexDirection: "row", marginBottom: 4, minWidth: 0 }}>
                    <Text style={{ color: logColor(l.step), fontSize: 11, fontWeight: "600", marginRight: 6 }}>
                      [{l.step}]
                    </Text>
                    {/* flexShrink + flex:1 để chuỗi dài tự xuống dòng trong khung, không lấn ra ngoài */}
                    <Text style={{ color: C.dim, fontSize: 11, flex: 1, flexShrink: 1, lineHeight: 15 }}>
                      {l.detail}
                    </Text>
                  </View>
                ))}
              </ScrollView>
            </View>
          )}
        </Card>
      )}

      <ScrollView ref={scroller} style={{ flex: 1 }} contentContainerStyle={{ padding: 12, gap: 10 }}>
        {hienThi.map((m, i) => (
          <Bubble key={i} m={m} />
        ))}
      </ScrollView>

      <View style={{ flexDirection: "row", gap: 8, padding: 12, paddingBottom: Platform.OS === "ios" ? 28 : 12, borderTopWidth: 1, borderTopColor: C.border, alignItems: "center" }}>
        <TextInput
          value={text}
          onChangeText={setText}
          onSubmitEditing={send}
          placeholder="Nhập tin nhắn…"
          placeholderTextColor={C.dim}
          style={{ flex: 1, backgroundColor: C.soft, borderColor: C.border, borderWidth: 1, borderRadius: 10, color: C.fg, paddingHorizontal: 12, paddingVertical: 10 }}
        />
        <Btn title="📎" kind="ghost" onPress={pickImage} />
        <Btn title="Gửi" onPress={send} />
      </View>
    </KeyboardAvoidingView>
  );
}

function Bubble({ m }) {
  const mine = m.direction === "out";
  const b = m.body;
  return (
    <View
      style={{
        alignSelf: mine ? "flex-end" : "flex-start",
        maxWidth: "82%",
        backgroundColor: mine ? "#143b2c" : "#1b2748",
        borderColor: mine ? "#1c5c44" : C.border,
        borderWidth: 1,
        borderRadius: 14,
        padding: 10,
      }}
    >
      {b.type === "file" ? (
        <View>
          <Text style={{ color: C.fg }}>📎 {b.name}</Text>
          {String(b.mime || "").startsWith("image/") && b.dataUri ? (
            <Image source={{ uri: b.dataUri }} style={{ width: 200, height: 150, borderRadius: 8, marginTop: 6 }} resizeMode="cover" />
          ) : null}
          <Text style={{ color: b.integrity ? C.accent : C.danger, fontSize: 11, marginTop: 4 }}>
            {b.integrity ? "toàn vẹn ✓ (SHA-256 khớp)" : "❌ sai toàn vẹn"}
          </Text>
        </View>
      ) : (
        <Text style={{ color: C.fg, fontSize: 15 }}>{b.text}</Text>
      )}
      <Text style={{ color: C.dim, fontSize: 10, marginTop: 4 }}>
        {mine ? "đã mã hóa gửi" : "đã giải mã ✓"}
      </Text>
    </View>
  );
}

function logColor(step) {
  if (["verify-ok", "derive", "safety"].includes(step)) return C.accent;
  if (["verify-fail", "decrypt-fail"].includes(step)) return C.danger;
  if (step === "warn") return C.warn;
  return C.accent2;
}
