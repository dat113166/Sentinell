// Màn khóa: khóa bí mật đang nằm trong gói bọc bằng mật khẩu, chưa nhập đúng thì app không
// có khóa nào để bắt tay — không nghe kết nối, không quảng bá mDNS, không đọc được lịch sử.
import React, { useState } from "react";
import { View, Text, TextInput } from "react-native";
import { Btn, Card, Muted, Mono } from "../ui";
import { C } from "../theme";

export default function LockScreen({ name, fp, onUnlock, notice }) {
  const [mk, setMk] = useState("");
  const [dang, setDang] = useState(false);
  const [tienDo, setTienDo] = useState(0);
  const [loi, setLoi] = useState(null);

  async function mo() {
    if (!mk || dang) return;
    setDang(true); setLoi(null); setTienDo(0);
    try {
      await onUnlock(mk, (p) => setTienDo(p));
    } catch (e) {
      setLoi(String(e?.message || e));
      setDang(false);
    }
  }

  return (
    <View style={{ flex: 1, backgroundColor: C.bg, justifyContent: "center", padding: 20 }}>
      <Text style={{ color: C.fg, fontSize: 26, fontWeight: "700", textAlign: "center", marginBottom: 6 }}>🔒 Sentinell</Text>
      <Muted style={{ textAlign: "center", marginBottom: 18 }}>{name} · {fp}</Muted>
      {notice ? <Muted style={{ textAlign: "center", color: notice.bad ? C.danger : C.dim, marginBottom: 12 }}>{notice.text}</Muted> : null}
      <Card>
        <Text style={{ color: C.fg, fontWeight: "600", marginBottom: 8 }}>Nhập mật khẩu để mở khóa</Text>
        <TextInput
          value={mk}
          onChangeText={setMk}
          secureTextEntry
          autoFocus
          editable={!dang}
          placeholder="Mật khẩu"
          placeholderTextColor={C.dim}
          onSubmitEditing={mo}
          style={{ backgroundColor: C.soft, borderColor: loi ? C.danger : C.border, borderWidth: 1, borderRadius: 8, color: C.fg, paddingHorizontal: 12, paddingVertical: 12 }}
        />
        {loi ? <Muted style={{ color: C.danger, marginTop: 8 }}>{loi}</Muted> : null}
        {dang ? (
          <View style={{ marginTop: 12 }}>
            <View style={{ height: 6, backgroundColor: C.soft, borderRadius: 3, overflow: "hidden" }}>
              <View style={{ width: tienDo < 0 ? "100%" : `${Math.round(tienDo * 100)}%`, height: 6, backgroundColor: tienDo < 0 ? C.accent2 : C.accent, opacity: tienDo < 0 ? 0.5 : 1 }} />
            </View>
            <Mono style={{ marginTop: 6 }}>Đang dẫn khóa từ mật khẩu (scrypt)… {tienDo < 0 ? "chạy native, chờ một chút" : `${Math.round(tienDo * 100)}%`}</Mono>
          </View>
        ) : null}
        <Btn title={dang ? "Đang mở…" : "Mở khóa"} onPress={mo} disabled={dang || !mk} style={{ marginTop: 12 }} />
      </Card>
      <Muted style={{ textAlign: "center", marginTop: 6 }}>
        Quên mật khẩu thì không ai mở được — kể cả người viết app. Khóa và lịch sử chỉ giải được bằng nó.
      </Muted>
    </View>
  );
}
