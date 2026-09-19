// Kiểm chứng mục "Đã xóa" và tài khoản cục bộ (mật khẩu).
//
//   node scripts/test-account.mjs
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { Storage } from "../desktop/server/storage.js";
import { genKeypair, fingerprint } from "@sentinell/core";

let loi = 0;
const dat = (ten, ok, them = "") => {
  console.log(`${ten.padEnd(56, " ")} ${ok ? "OK" : "SAI"}${them ? "   " + them : ""}`);
  if (!ok) loi++;
};
const moi = () => fs.mkdtempSync(path.join(os.tmpdir(), "sentinell-tk-"));

// ==================================================== mục "Đã xóa"
console.log("--- mục Đã xóa ---");
{
  const d = moi();
  const kho = await Storage.open(path.join(d, "data"), null);
  const a = genKeypair(), b = genKeypair();
  const fpA = fingerprint(a.pub);
  kho.pinContact(a.pub, "Máy A");
  kho.pinContact(b.pub, "Máy B");
  kho.saveMessage(a.pub, "in", { type: "text", text: "mật khẩu wifi là 12345678" });
  kho.saveMessage(a.pub, "out", { type: "text", text: "ok nhớ rồi" });
  kho.saveMessage(b.pub, "in", { type: "text", text: "mật khẩu cửa là 1111" });

  dat("trước khi xóa: tìm ra cả 2 cuộc", kho.searchMessages("mat khau").items.length === 2);

  const so = kho.trashChat(a.pub);
  dat("chuyển vào thùng rác đúng số tin", so === 2, `(${so})`);
  dat("ĐÃ XÓA THÌ KHÔNG TÌM RA NỮA", kho.searchMessages("mat khau").items.length === 1);
  dat("lịch sử cuộc đó cũng rỗng", kho.loadHistory(a.pub).length === 0);
  dat("dòng xem trước cũng biến mất", kho.lastMessage(a.pub) === null);
  dat("liên hệ bị gỡ khỏi danh bạ", !kho.contacts[fpA]);
  dat("nhưng vẫn nằm trong mục Đã xóa", kho.listTrash().length === 1 && kho.listTrash()[0].count === 2);
  dat("cuộc trò chuyện KHÁC không bị đụng tới", kho.loadHistory(b.pub).length === 1);

  const t = kho.restoreChat(fpA);
  dat("khôi phục: tin nhắn quay lại", kho.loadHistory(a.pub).length === 2 && !!t);
  dat("khôi phục: tìm kiếm thấy lại", kho.searchMessages("mat khau").items.length === 2);
  dat("khôi phục: khóa đã ghim được trả lại", !!kho.contacts[fpA]);
  dat("khôi phục: mục Đã xóa rỗng", kho.listTrash().length === 0);

  kho.trashChat(a.pub);
  kho.purgeChat(fpA);
  dat("xóa vĩnh viễn: mục Đã xóa rỗng", kho.listTrash().length === 0);
  dat("xóa vĩnh viễn: khôi phục không còn tác dụng", kho.restoreChat(fpA) === null);
  dat("xóa vĩnh viễn: dữ liệu biến mất khỏi kho", kho.loadHistory(a.pub).length === 0);
  const tho = fs.readFileSync(path.join(d, "data", "messages.db"));
  dat("xóa vĩnh viễn: cả peer_pub cũng không còn", !tho.includes(Buffer.from(a.pub, "utf8")));
  fs.rmSync(d, { recursive: true, force: true });
}

// ==================================================== tài khoản cục bộ
console.log("\n--- tài khoản cục bộ ---");
{
  const d = moi();
  const thuMuc = path.join(d, "data");
  let kho = await Storage.open(thuMuc, null);
  const pubGoc = kho.idPub, privGoc = kho.idPriv;
  const a = genKeypair();
  kho.pinContact(a.pub, "Máy A");
  kho.saveMessage(a.pub, "in", { type: "text", text: "bí mật của tôi" });

  dat("ban đầu chưa có tài khoản", kho.hasAccount === false && kho.locked === false);

  let batLoi = null;
  try { await kho.createAccount("ngan"); } catch (e) { batLoi = e.message; }
  dat("từ chối mật khẩu ngắn", /8 ký tự/.test(batLoi || ""));

  await kho.createAccount("matkhau-rat-manh-2026");
  dat("đặt mật khẩu xong", kho.hasAccount === true);

  const tren = JSON.parse(fs.readFileSync(path.join(thuMuc, "identity.json"), "utf8"));
  dat("identity.json KHÔNG còn khóa bí mật bản rõ", !tren.priv && !tren.storage_key);
  dat("identity.json không chứa chuỗi khóa bí mật",
    !fs.readFileSync(path.join(thuMuc, "identity.json"), "utf8").includes(privGoc));
  dat("có gói scrypt + salt + bản mã", tren.account?.kdf === "scrypt"
    && tren.account.salt.length === 32 && tren.account.ct.length > 0);

  // Mở lại kho như lúc khởi động app
  kho = await Storage.open(thuMuc, null);
  dat("mở app lần sau: đang KHÓA", kho.locked === true && kho.hasAccount === true);
  dat("đang khóa thì chưa có khóa bí mật trong RAM", kho.idPriv === undefined);

  batLoi = null;
  try { await kho.unlock("sai-mat-khau-roi"); } catch (e) { batLoi = e.message; }
  dat("sai mật khẩu → từ chối", /không đúng/.test(batLoi || "") && kho.locked === true);

  await kho.unlock("matkhau-rat-manh-2026");
  dat("đúng mật khẩu → mở được", kho.locked === false);
  dat("khóa danh tính y như cũ", kho.idPub === pubGoc && kho.idPriv === privGoc);
  dat("đọc lại được tin nhắn cũ", kho.loadHistory(a.pub)[0]?.body.text === "bí mật của tôi");
  dat("tìm kiếm chạy lại bình thường", kho.searchMessages("bi mat").items.length === 1);

  // Khóa lại giữa chừng
  kho.lock();
  dat("khóa lại: bí mật rời khỏi RAM", kho.locked === true && kho.idPriv === undefined);
  await kho.unlock("matkhau-rat-manh-2026");
  dat("mở lại lần nữa vẫn được", kho.locked === false && kho.idPriv === privGoc);

  // Xoay khóa khi đang có tài khoản — phải bọc lại gói, nếu không lần sau mở ra khóa cũ
  const khoaMoi = kho.rotateIdentity();
  const privSauXoay = kho.idPriv;
  kho = await Storage.open(thuMuc, null);
  await kho.unlock("matkhau-rat-manh-2026");
  dat("xoay khóa rồi mở lại: ra ĐÚNG khóa mới",
    kho.idPub === khoaMoi.pub && kho.idPriv === privSauXoay);

  // Đổi mật khẩu
  batLoi = null;
  try { await kho.changePassword("sai-hoan-toan", "mat-khau-moi-2026"); } catch (e) { batLoi = e.message; }
  dat("đổi mật khẩu: sai mật khẩu cũ → từ chối", /hiện tại không đúng/.test(batLoi || ""));
  await kho.changePassword("matkhau-rat-manh-2026", "mat-khau-moi-2026");
  kho = await Storage.open(thuMuc, null);
  batLoi = null;
  try { await kho.unlock("matkhau-rat-manh-2026"); } catch (e) { batLoi = e.message; }
  dat("mật khẩu CŨ hết tác dụng", !!batLoi && kho.locked === true);
  await kho.unlock("mat-khau-moi-2026");
  dat("mật khẩu MỚI mở được", kho.locked === false);

  // Xuất sang máy khác
  const tep = kho.exportAccount();
  const vanBan = JSON.stringify(tep);
  dat("tệp xuất KHÔNG chứa khóa bí mật bản rõ", !vanBan.includes(kho.idPriv));
  dat("tệp xuất mang theo danh bạ", Object.keys(tep.contacts).length === 1);

  const d2 = moi();
  const khoMoi = await Storage.open(path.join(d2, "data"), null);
  batLoi = null;
  try { await khoMoi.importAccount(tep, "doan-bay-mat-khau"); } catch (e) { batLoi = e.message; }
  dat("máy mới: sai mật khẩu → không nhận", /không mở được/.test(batLoi || ""));
  const r = await khoMoi.importAccount(tep, "mat-khau-moi-2026");
  dat("máy mới: đúng mật khẩu → nhận được danh tính",
    khoMoi.idPub === kho.idPub && khoMoi.idPriv === kho.idPriv);
  dat("máy mới: danh bạ đi theo", r.contacts === 1 && !!khoMoi.contacts[fingerprint(a.pub)]);
  dat("máy mới: lịch sử KHÔNG đi theo", khoMoi.loadHistory(a.pub).length === 0);

  const lai = await Storage.open(path.join(d2, "data"), null);
  dat("máy mới: mở app lần sau vẫn hỏi mật khẩu", lai.locked === true);
  await lai.unlock("mat-khau-moi-2026");
  dat("máy mới: mở khóa bằng đúng mật khẩu đó", lai.idPub === kho.idPub);

  // Bỏ mật khẩu
  await kho.removeAccount("mat-khau-moi-2026");
  const sau = await Storage.open(thuMuc, null);
  dat("bỏ mật khẩu: mở thẳng, không hỏi nữa", sau.locked === false && sau.hasAccount === false);
  dat("bỏ mật khẩu: vẫn đúng khóa và đọc được kho", sau.idPub === khoaMoi.pub);

  fs.rmSync(d, { recursive: true, force: true });
  fs.rmSync(d2, { recursive: true, force: true });
}

// ============================== cột trò chuyện phải khớp với tìm kiếm
// Lỗi thật đã gặp: cột trò chuyện dựng từ DANH BẠ (khóa đã ghim), nên hội thoại với
// thiết bị chưa ghim biến mất khỏi danh sách — trong khi tìm kiếm vẫn moi ra được.
console.log("\n--- cột trò chuyện vs tìm kiếm ---");
{
  const d = moi();
  const kho = await Storage.open(path.join(d, "data"), null);
  const ghim = genKeypair(), chuaGhim = genKeypair();

  kho.pinContact(ghim.pub, "Máy đã ghim");
  kho.saveMessage(ghim.pub, "in", { type: "text", text: "xin chào từ máy đã ghim" });
  // thiết bị lạ gọi sang, mình bấm Chấp nhận: có lịch sử nhưng KHÔNG ghim khóa
  kho.rememberPeer(chuaGhim.pub, "Thiết bị lạ");
  kho.saveMessage(chuaGhim.pub, "in", { type: "text", text: "xin chào từ máy chưa ghim" });

  const ds = kho.listConversations();
  dat("cả hai đều có mặt trong cột trò chuyện", ds.length === 2);
  dat("đánh dấu đúng cái nào đã ghim khóa",
    ds.find((c) => c.pub === ghim.pub)?.pinned === true
    && ds.find((c) => c.pub === chuaGhim.pub)?.pinned === false);

  const kq = kho.searchMessages("xin chao").items;
  dat("tìm kiếm ra 2 kết quả", kq.length === 2);
  dat("MỌI kết quả tìm được đều mở lại được từ cột",
    kq.every((m) => ds.some((c) => c.pub === m.peer_pub)));

  // kho đời cũ: có lịch sử nhưng chưa từng ghi tên (known.json trống)
  const motoi = genKeypair();
  kho.saveMessage(motoi.pub, "in", { type: "text", text: "lịch sử mồ côi" });
  const ds2 = kho.listConversations();
  dat("lịch sử mồ côi vẫn hiện ra, không bị bỏ quên", ds2.length === 3);
  dat("mọi kết quả tìm vẫn có chỗ trong cột",
    kho.searchMessages("lich su").items.every((m) => ds2.some((c) => c.pub === m.peer_pub)));

  // xóa cuộc chưa ghim: phải rời cả cột lẫn tìm kiếm
  kho.trashChat(chuaGhim.pub, "Thiết bị lạ");
  dat("xóa cuộc chưa ghim: rời khỏi cột trò chuyện",
    !kho.listConversations().some((c) => c.pub === chuaGhim.pub));
  dat("xóa cuộc chưa ghim: không còn tìm ra",
    !kho.searchMessages("xin chao").items.some((m) => m.peer_pub === chuaGhim.pub));
  kho.restoreChat(fingerprint(chuaGhim.pub));
  const ds3 = kho.listConversations();
  dat("khôi phục: quay lại cột, vẫn là CHƯA ghim",
    ds3.find((c) => c.pub === chuaGhim.pub)?.pinned === false);
  fs.rmSync(d, { recursive: true, force: true });
}

// ============================== sao lưu gộp với mật khẩu
console.log("\n--- sao lưu luôn được mã hóa ---");
{
  const d = moi();
  const kho = await Storage.open(path.join(d, "data"), null);
  const a = genKeypair();
  kho.pinContact(a.pub, "Bạn");

  dat("máy CHƯA đặt mật khẩu vẫn sao lưu được", (() => {
    const t = kho.exportAccount("mat-khau-tep-2026");
    return t.kind === "sentinell-account" && !!t.account.ct;
  })());
  let e1 = null;
  try { kho.exportAccount("ngan"); } catch (e) { e1 = e.message; }
  dat("sao lưu không mật khẩu / mật khẩu ngắn → từ chối", /8 ký tự/.test(e1 || ""));

  const tep = kho.exportAccount("mat-khau-tep-2026");
  dat("tệp KHÔNG chứa khóa bí mật bản rõ", !JSON.stringify(tep).includes(kho.idPriv));
  dat("sao lưu KHÔNG tự biến máy thành có tài khoản", kho.hasAccount === false);

  const d2 = moi();
  const kho2 = await Storage.open(path.join(d2, "data"), null);
  await kho2.importAccount(tep, "mat-khau-tep-2026");
  dat("phục hồi ở máy khác ra đúng khóa", kho2.idPub === kho.idPub && kho2.idPriv === kho.idPriv);
  dat("máy phục hồi nay dùng mật khẩu của tệp", kho2.hasAccount === true);
  fs.rmSync(d, { recursive: true, force: true });
  fs.rmSync(d2, { recursive: true, force: true });
}

// ============================== tham số scrypt phải bám theo TỪNG tài khoản
// Lỗi đã có thật: N/r/p được GHI vào tệp nhưng chẳng bao giờ đọc lại — mọi lần dẫn khóa
// đều dùng tham số hiện hành. Nghĩa là hễ nâng tham số lên là mọi tài khoản đã tạo trở
// nên KHÔNG MỞ ĐƯỢC NỮA, mất sạch khóa lẫn lịch sử.
console.log("\n--- tham số scrypt theo từng tài khoản ---");
{
  const d = moi();
  const thuMuc = path.join(d, "data");
  let kho = await Storage.open(thuMuc, null);
  const pubGoc = kho.idPub;
  await kho.createAccount("mat-khau-manh-2026");

  // Giả một tài khoản tạo bằng BẢN CŨ: hạ tham số xuống rồi bọc lại bằng đúng tham số đó.
  const cu = { kdf: "scrypt", N: 32768, r: 8, p: 1 };
  const salt = kho.identity.account.salt;
  kho._kdf = cu;
  kho._kek = kho._dansuatKek("mat-khau-manh-2026", salt, cu);
  kho._boclaiTaiKhoan();
  kho._saveIdentity();
  const tren = JSON.parse(fs.readFileSync(path.join(thuMuc, "identity.json"), "utf8"));
  dat("dựng được tài khoản kiểu cũ (N=2^15)", tren.account.N === 32768);
  dat("bản mới mặc định dùng N=2^17 (khuyến nghị OWASP)", Storage.KDF.N === 131072);

  kho = await Storage.open(thuMuc, null);
  await kho.unlock("mat-khau-manh-2026");
  dat("TÀI KHOẢN CŨ VẪN MỞ ĐƯỢC sau khi nâng tham số", kho.locked === false && kho.idPub === pubGoc);

  // Xoay khóa khi đang dùng tài khoản kiểu cũ: gói phải giữ NGUYÊN tham số cũ,
  // vì KEK đang giữ là của tham số cũ.
  const khoaMoi = kho.rotateIdentity();
  const sau = JSON.parse(fs.readFileSync(path.join(thuMuc, "identity.json"), "utf8"));
  dat("xoay khóa KHÔNG làm lệch tham số trong gói", sau.account.N === 32768);
  kho = await Storage.open(thuMuc, null);
  await kho.unlock("mat-khau-manh-2026");
  dat("mở lại sau khi xoay khóa vẫn đúng khóa mới", kho.idPub === khoaMoi.pub);

  // Đổi mật khẩu là dịp nâng tham số lên mức hiện hành.
  await kho.changePassword("mat-khau-manh-2026", "mat-khau-moi-2026");
  const sau2 = JSON.parse(fs.readFileSync(path.join(thuMuc, "identity.json"), "utf8"));
  dat("đổi mật khẩu → nâng tham số lên mức mới", sau2.account.N === 131072);
  kho = await Storage.open(thuMuc, null);
  await kho.unlock("mat-khau-moi-2026");
  dat("và vẫn mở được bằng mật khẩu mới", kho.locked === false);
  fs.rmSync(d, { recursive: true, force: true });
}

// ============================== nâng cấp từ kho đời cũ
// Máy đang dùng bản 3.8.0 trở về trước có bảng `messages` KHÔNG có cột deleted_at.
// Mở bằng bản mới mà không tự thêm cột thì mọi truy vấn đều lỗi và mất sạch lịch sử.
console.log("\n--- nâng cấp kho đời cũ ---");
{
  const require = createRequire(import.meta.url);
  const initSqlJs = require("sql.js");
  const d = moi();
  const data = path.join(d, "data");

  const kho0 = await Storage.open(data, null);
  const a = genKeypair();
  kho0.pinContact(a.pub, "Bạn cũ");
  kho0.saveMessage(a.pub, "in", { type: "text", text: "tin nhắn từ bản cũ" });

  // hạ cấp bảng cho giống hệt kho đời trước
  const SQL = await initSqlJs({ locateFile: (f) => require.resolve(`sql.js/dist/${f}`) });
  const db = new SQL.Database(fs.readFileSync(path.join(data, "messages.db")));
  db.run(`CREATE TABLE cu(id INTEGER PRIMARY KEY AUTOINCREMENT, peer_pub TEXT, direction TEXT, ts REAL, nonce BLOB, body_ct BLOB);
          INSERT INTO cu(id,peer_pub,direction,ts,nonce,body_ct) SELECT id,peer_pub,direction,ts,nonce,body_ct FROM messages;
          DROP TABLE messages; ALTER TABLE cu RENAME TO messages;`);
  fs.writeFileSync(path.join(data, "messages.db"), Buffer.from(db.export()));
  db.close();

  const kho = await Storage.open(data, null);
  dat("mở được kho đời cũ", !!kho.db);
  dat("tin nhắn cũ còn nguyên", kho.loadHistory(a.pub)[0]?.body.text === "tin nhắn từ bản cũ");
  dat("tìm kiếm chạy trên kho cũ", kho.searchMessages("ban cu").items.length === 1);
  kho.trashChat(a.pub);
  dat("xóa vào mục Đã xóa chạy được", kho.listTrash()[0]?.count === 1);
  dat("xóa rồi thì không tìm ra", kho.searchMessages("ban cu").items.length === 0);
  fs.rmSync(d, { recursive: true, force: true });
}

console.log(loi === 0 ? "\nTẤT CẢ ĐẠT" : `\n${loi} MỤC SAI`);
process.exit(loi === 0 ? 0 : 1);
