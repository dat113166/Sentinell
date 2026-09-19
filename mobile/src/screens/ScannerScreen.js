// Quét QR bằng camera (expo-camera SDK 57: CameraView + useCameraPermissions).
// Nhận được 3 dạng mã (xem src/qr.js): lời mời của máy tính, khóa công khai, hoặc ip:port.
import React, { useState } from "react";
import { View, Text, Platform } from "react-native";
import { CameraView, useCameraPermissions } from "expo-camera";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { parseQr } from "../qr";
import { Btn, Card, H2, Muted } from "../ui";
import { C } from "../theme";

export default function ScannerScreen({ onResult, onCancel }) {
  const [permission, requestPermission] = useCameraPermissions();
  const [locked, setLocked] = useState(false); // chống quét lặp liên tục
  const insets = useSafeAreaInsets(); // camera tràn màn hình, chữ và nút tránh thanh hệ thống

  function handle({ data }) {
    if (locked) return;
    setLocked(true);
    onResult(parseQr(data));
  }

  if (Platform.OS === "web") {
    return (
      <View style={wrap}>
        <Card>
          <H2>Camera không dùng được ở bản web</H2>
          <Muted>Hãy mở app bằng Expo Go trên điện thoại để quét QR, hoặc dùng “Kết nối thủ công”.</Muted>
          <Btn title="Quay lại" kind="ghost" style={{ marginTop: 12 }} onPress={onCancel} />
        </Card>
      </View>
    );
  }

  if (!permission) {
    return <View style={wrap}><Muted>Đang kiểm tra quyền camera…</Muted></View>;
  }

  if (!permission.granted) {
    return (
      <View style={wrap}>
        <Card>
          <H2>Cần quyền camera</H2>
          <Muted>Sentinell dùng camera chỉ để đọc mã QR chứa khóa công khai — ảnh không rời khỏi máy.</Muted>
          <Btn title="Cấp quyền camera" style={{ marginTop: 12 }} onPress={requestPermission} />
          <Btn title="Quay lại" kind="ghost" style={{ marginTop: 8 }} onPress={onCancel} />
        </Card>
      </View>
    );
  }

  return (
    <View style={{ flex: 1, backgroundColor: "#000" }}>
      <CameraView
        style={{ flex: 1 }}
        facing="back"
        barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
        onBarcodeScanned={locked ? undefined : handle}
      />
      <View style={{ position: "absolute", top: 0, left: 0, right: 0, padding: 20, paddingTop: insets.top + 20 }}>
        <Text style={{ color: "#fff", fontSize: 16, fontWeight: "600", textAlign: "center" }}>
          Đưa mã QR trên màn hình máy tính vào khung hình
        </Text>
      </View>
      <View style={{ position: "absolute", bottom: 0, left: 0, right: 0, padding: 20, paddingBottom: insets.bottom + 20 }}>
        <Btn title="Hủy" kind="ghost" onPress={onCancel} />
      </View>
    </View>
  );
}

const wrap = { flex: 1, backgroundColor: C.bg, justifyContent: "center", padding: 16 };
