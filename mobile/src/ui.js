// Vài thành phần giao diện dùng lại, cho đồng bộ với bản web.
import React from "react";
import { Text, TouchableOpacity, View, StyleSheet } from "react-native";
import { C } from "./theme";

export function Btn({ title, onPress, kind = "primary", style, disabled }) {
  const bg = disabled ? C.border : kind === "primary" ? C.accent : kind === "danger" ? C.danger : C.soft;
  const fg = disabled ? C.dim : kind === "primary" ? "#052015" : kind === "danger" ? "#2a0410" : C.fg;
  return (
    <TouchableOpacity
      onPress={disabled ? undefined : onPress}
      activeOpacity={0.8}
      style={[s.btn, { backgroundColor: bg, borderColor: kind === "ghost" ? C.border : "transparent" }, style]}
    >
      <Text style={[s.btnText, { color: fg }]}>{title}</Text>
    </TouchableOpacity>
  );
}

export function Card({ children, style }) {
  return <View style={[s.card, style]}>{children}</View>;
}

export function Pill({ text, kind = "dim" }) {
  const map = {
    ok: { c: C.accent, bg: "#0e2a20", b: "#1c5c44" },
    warn: { c: C.warn, bg: "#2a230e", b: "#5c4a1c" },
    bad: { c: C.danger, bg: "#2a0410", b: "#5c1c2c" },
    dim: { c: C.dim, bg: C.soft, b: C.border },
  }[kind];
  return (
    <View style={[s.pill, { backgroundColor: map.bg, borderColor: map.b }]}>
      <Text style={{ color: map.c, fontSize: 12 }}>{text}</Text>
    </View>
  );
}

export function H2({ children }) {
  return <Text style={s.h2}>{children}</Text>;
}
export function Muted({ children, style }) {
  return <Text style={[s.muted, style]}>{children}</Text>;
}
export function Mono({ children, style }) {
  return <Text style={[s.mono, style]}>{children}</Text>;
}

export const s = StyleSheet.create({
  btn: { paddingVertical: 13, paddingHorizontal: 16, borderRadius: 10, alignItems: "center", borderWidth: 1 },
  btnText: { fontWeight: "600", fontSize: 15 },
  card: { backgroundColor: C.card, borderColor: C.border, borderWidth: 1, borderRadius: 14, padding: 16, marginBottom: 14 },
  h2: { color: C.fg, fontSize: 16, fontWeight: "700", marginBottom: 8 },
  muted: { color: C.dim, fontSize: 13, lineHeight: 19 },
  mono: { color: C.dim, fontSize: 12, fontFamily: undefined, letterSpacing: 0.5 },
  pill: { paddingHorizontal: 9, paddingVertical: 3, borderRadius: 999, borderWidth: 1, alignSelf: "flex-start" },
});
