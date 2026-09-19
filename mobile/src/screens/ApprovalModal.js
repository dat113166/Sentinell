// Hộp duyệt kết nối đến từ một khóa CHƯA ghim — giống hộp "Chấp nhận / Từ chối" của desktop.
// Cố ý không cho bấm nền để đóng: phải chọn một cách có ý thức (bài học desktop, mục 29).
import React from "react";
import { Modal, View, Text } from "react-native";
import { Btn, Muted, Mono } from "../ui";
import { C } from "../theme";

export default function ApprovalModal({ req, onAccept, onReject }) {
  return (
    <Modal visible={!!req} transparent animationType="fade" onRequestClose={() => {}}>
      <View style={{ flex: 1, backgroundColor: "rgba(4,8,20,0.78)", justifyContent: "center", padding: 20 }}>
        <View style={{ backgroundColor: C.card, borderColor: C.warn, borderWidth: 1, borderRadius: 16, padding: 18 }}>
          <Text style={{ color: C.fg, fontSize: 18, fontWeight: "700", marginBottom: 8 }}>
            📲 Thiết bị lạ muốn kết nối
          </Text>
          <Text style={{ color: C.fg, fontSize: 16, marginBottom: 6 }}>{req?.name}</Text>
          <Mono>vân tay: {req?.fp}</Mono>
          {req?.host ? <Mono>từ địa chỉ: {req.host}</Mono> : null}
          <Muted style={{ marginTop: 10 }}>
            Khóa này chưa được ghim. Chỉ chấp nhận nếu bạn biết đó là ai — và sau khi vào phòng, hãy
            đối chiếu safety number với họ. Tự từ chối sau 60 giây.
          </Muted>
          <View style={{ flexDirection: "row", gap: 10, marginTop: 16 }}>
            <Btn title="Từ chối" kind="danger" style={{ flex: 1 }} onPress={onReject} />
            <Btn title="Chấp nhận" style={{ flex: 1 }} onPress={onAccept} />
          </View>
        </View>
      </View>
    </Modal>
  );
}
