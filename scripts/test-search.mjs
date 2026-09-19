// Kiểm chứng tìm kiếm trong lịch sử: bỏ dấu, không phân biệt hoa/thường, tìm cả tên tệp,
// và chứng minh vì sao KHÔNG thể dùng LIKE của SQL (nội dung mã hóa at-rest).
//
//   node scripts/test-search.mjs
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Storage } from "../desktop/server/storage.js";

let loi = 0;
const dat = (ten, ok, them = "") => {
  console.log(`${ten.padEnd(54, " ")} ${ok ? "OK" : "SAI"}${them ? "   " + them : ""}`);
  if (!ok) loi++;
};

const thuMuc = fs.mkdtempSync(path.join(os.tmpdir(), "sentinell-tim-"));
const kho = await Storage.open(path.join(thuMuc, "data"), null);

const A = "03" + "a".repeat(64);
const B = "03" + "b".repeat(64);
let t = 1_700_000_000;
const luu = (pub, huong, body) => kho.saveMessage(pub, huong, body, t++);

luu(A, "in",  { type: "text", text: "Mai họp nhóm đồ án lúc 8 giờ nhé" });
luu(A, "out", { type: "text", text: "Ok, tôi mang Báo cáo bản in theo" });
luu(A, "out", { type: "file", name: "báo cáo ATBMTT.pdf", mime: "application/pdf", size: 10 });
luu(B, "in",  { type: "text", text: "Đã gửi ảnh chụp màn hình rồi đấy" });
luu(B, "in",  { type: "file", name: "man-hinh.png", mime: "image/png", size: 10 });
luu(A, "in",  { type: "text", text: "ĐỪNG QUÊN mang thẻ sinh viên" });

const tim = (q, o) => kho.searchMessages(q, o);

dat("tìm đúng chữ có dấu", tim("Báo cáo").items.length === 2);
dat("gõ KHÔNG dấu vẫn ra", tim("bao cao").items.length === 2);
dat("không phân biệt hoa/thường", tim("BÁO CÁO").items.length === 2);
dat("tìm được trong tên tệp", tim("ATBMTT").items.some((m) => m.kind === "file"));
dat("chữ 'đ' bỏ dấu đúng (do an → đồ án)", tim("do an").items.length === 1);
dat("gõ 'dung quen' ra 'ĐỪNG QUÊN'", tim("dung quen").items.length === 1);
dat("không khớp thì trả về rỗng", tim("xyzzy").items.length === 0);
dat("lọc theo một liên hệ", tim("a", { peerPub: B }).items.every((m) => m.peer_pub === B));

const moi = tim("a").items;
dat("kết quả xếp MỚI trước", moi.length > 1 && moi[0].ts > moi[moi.length - 1].ts);

const it = tim("a", { limit: 2 });
dat("tôn trọng giới hạn + báo còn nữa", it.items.length === 2 && it.truncated === true);

const mot = tim("thẻ sinh viên").items[0];
dat("trả về đủ thông tin để mở lại đúng chỗ",
  mot && mot.peer_pub === A && mot.direction === "in" && typeof mot.ts === "number");

// Đoạn trích: tin dài thì phải cắt quanh chỗ khớp chứ không gửi cả bài về giao diện.
luu(A, "in", { type: "text", text: "x".repeat(400) + " mật khẩu wifi là 12345678 " + "y".repeat(400) });
const dai = tim("mật khẩu wifi").items[0];
dat("cắt đoạn quanh chỗ khớp", dai && dai.text.length < 200 && dai.text.includes("mật khẩu wifi"),
  `(${dai?.text.length} ký tự)`);
dat("có dấu … báo là đã cắt", dai && dai.text.startsWith("…") && dai.text.endsWith("…"));

// Vì sao phải giải mã từng dòng: trong tệp .db KHÔNG có chữ nào ở dạng đọc được.
const tho = fs.readFileSync(path.join(thuMuc, "data", "messages.db"));
const hien = (s) => tho.includes(Buffer.from(s, "utf8"));
dat("tệp .db KHÔNG chứa nội dung dạng đọc được",
  !hien("mật khẩu wifi") && !hien("Báo cáo") && !hien("ATBMTT"));
dat("tệp .db vẫn có cột peer_pub (chỉ nội dung bị mã hóa)", hien(A));

fs.rmSync(thuMuc, { recursive: true, force: true });
console.log(loi === 0 ? "\nTẤT CẢ ĐẠT" : `\n${loi} MỤC SAI`);
process.exit(loi === 0 ? 0 : 1);
