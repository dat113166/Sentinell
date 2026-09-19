// Hộp nhập mật khẩu cho ba việc: đặt, đổi, bỏ. Dẫn khóa scrypt mất cả giây trên điện thoại,
// nên có thanh tiến độ — không thì người dùng tưởng app treo rồi bấm lung tung.
import React, { useEffect, useState } from "react";
import { Modal, View, Text, TextInput } from "react-native";
import { Btn, Muted, Mono } from "../ui";
import { C } from "../theme";

const TIEU_DE = { tao: "Đặt mật khẩu cho máy này", doi: "Đổi mật khẩu", bo: "Bỏ mật khẩu" };

export default function PasswordModal({ mode, onSubmit, onClose }) {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [c, setC] = useState("");
  const [dang, setDang] = useState(false);
  const [tienDo, setTienDo] = useState(0);
  const [loi, setLoi] = useState(null);

  useEffect(() => { setA(""); setB(""); setC(""); setLoi(null); setDang(false); setTienDo(0); }, [mode]);

  async function xong() {
    setLoi(null);
    if (mode === "tao" && a !== b) { setLoi("Hai lần nhập không khớp."); return; }
    if (mode === "doi" && b !== c) { setLoi("Mật khẩu mới nhập lại không khớp."); return; }
    setDang(true); setTienDo(0);
    try {
      await onSubmit(a, mode === "doi" ? b : null, (p) => setTienDo(p));
      onClose();
    } catch (e) {
      setLoi(String(e?.message || e));
      setDang(false);
    }
  }

  const o = (value, set, placeholder, extra = {}) => (
    <TextInput
      value={value} onChangeText={set} secureTextEntry editable={!dang}
      placeholder={placeholder} placeholderTextColor={C.dim}
      style={{ backgroundColor: C.soft, borderColor: C.border, borderWidth: 1, borderRadius: 8, color: C.fg, paddingHorizontal: 12, paddingVertical: 11, marginTop: 8 }}
      {...extra}
    />
  );

  return (
    <Modal visible={!!mode} transparent animationType="fade" onRequestClose={() => !dang && onClose()}>
      <View style={{ flex: 1, backgroundColor: "rgba(4,8,20,0.78)", justifyContent: "center", padding: 20 }}>
        <View style={{ backgroundColor: C.card, borderColor: C.border, borderWidth: 1, borderRadius: 16, padding: 18 }}>
          <Text style={{ color: C.fg, fontSize: 17, fontWeight: "700" }}>{TIEU_DE[mode] || ""}</Text>
          {mode === "tao" ? (
            <Muted style={{ marginTop: 6 }}>
              Khóa bí mật sẽ được bọc bằng khóa dẫn từ mật khẩu (scrypt → AES-256-GCM). Quên mật khẩu là
              mất khóa và lịch sử — không có cách khôi phục. Tối thiểu 8 ký tự.
            </Muted>
          ) : null}
          {mode === "bo" ? (
            <Muted style={{ marginTop: 6 }}>Bỏ mật khẩu thì khóa chỉ còn được Keystore của Android bảo vệ.</Muted>
          ) : null}
          {mode === "tao" && (<>{o(a, setA, "Mật khẩu mới", { autoFocus: true })}{o(b, setB, "Nhập lại mật khẩu")}</>)}
          {mode === "doi" && (<>{o(a, setA, "Mật khẩu hiện tại", { autoFocus: true })}{o(b, setB, "Mật khẩu mới")}{o(c, setC, "Nhập lại mật khẩu mới")}</>)}
          {mode === "bo" && o(a, setA, "Mật khẩu hiện tại", { autoFocus: true })}
          {loi ? <Muted style={{ color: C.danger, marginTop: 8 }}>{loi}</Muted> : null}
          {dang ? (
            <View style={{ marginTop: 12 }}>
              <View style={{ height: 6, backgroundColor: C.soft, borderRadius: 3, overflow: "hidden" }}>
                <View style={{ width: tienDo < 0 ? "100%" : `${Math.round(tienDo * 100)}%`, height: 6, backgroundColor: tienDo < 0 ? C.accent2 : C.accent, opacity: tienDo < 0 ? 0.5 : 1 }} />
              </View>
              <Mono style={{ marginTop: 6 }}>Đang dẫn khóa (scrypt)… {tienDo < 0 ? "chạy native, chờ một chút" : `${Math.round(tienDo * 100)}%`}</Mono>
            </View>
          ) : null}
          <View style={{ flexDirection: "row", gap: 10, marginTop: 14 }}>
            <Btn title="Hủy" kind="ghost" style={{ flex: 1 }} onPress={onClose} disabled={dang} />
            <Btn title={mode === "bo" ? "Bỏ mật khẩu" : "Lưu"} kind={mode === "bo" ? "danger" : "primary"} style={{ flex: 1 }} onPress={xong} disabled={dang || !a} />
          </View>
        </View>
      </View>
    </Modal>
  );
}
