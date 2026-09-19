// Sinh icon khiên cho khay hệ thống (assets/tray.png, assets/tray@2x.png).
// Tự ghi PNG bằng zlib để khỏi thêm phụ thuộc chỉ vì một cái icon 32px.
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(here, "../assets");

/** Điểm (x,y) có nằm trong hình khiên không — toạ độ đã chuẩn hoá theo cạnh S. */
function trongKhien(x, y, S) {
  const nx = (x - S / 2) / (S * 0.345);          // nửa bề ngang
  const ny = (y - S * 0.125) / (S * 0.78);       // từ đỉnh xuống mũi nhọn
  if (ny < 0 || ny > 1) return false;
  let nua = 1;
  if (ny > 0.55) nua = 1 - Math.pow((ny - 0.55) / 0.45, 1.5);   // vuốt nhọn xuống đáy
  if (ny < 0.14) {                                              // bo tròn hai vai
    const t = (0.14 - ny) / 0.14;
    nua *= Math.sqrt(Math.max(0, 1 - t * t));
  }
  return Math.abs(nx) <= nua;
}

function vePng(S) {
  const R = 0x3d, G = 0xdc, B = 0x97;            // xanh nhấn của app
  const hang = [];
  for (let y = 0; y < S; y++) {
    const d = [0];                                // byte filter = 0 (None)
    for (let x = 0; x < S; x++) {
      // khử răng cưa bằng cách lấy mẫu 3×3 trong mỗi điểm ảnh
      let trong = 0;
      for (let sy = 0; sy < 3; sy++) {
        for (let sx = 0; sx < 3; sx++) {
          if (trongKhien(x + (sx + 0.5) / 3, y + (sy + 0.5) / 3, S)) trong++;
        }
      }
      const a = Math.round((trong / 9) * 255);
      d.push(R, G, B, a);
    }
    hang.push(Buffer.from(d));
  }

  const chunk = (ten, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(ten, "ascii"), data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body) >>> 0);
    return Buffer.concat([len, body, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(S, 0); ihdr.writeUInt32BE(S, 4);
  ihdr[8] = 8;      // 8 bit mỗi kênh
  ihdr[9] = 6;      // RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(Buffer.concat(hang), { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

let bang = null;
function crc32(buf) {
  if (!bang) {
    bang = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      bang[n] = c;
    }
  }
  let c = 0xffffffff;
  for (const b of buf) c = bang[(c ^ b) & 0xff] ^ (c >>> 8);
  return c ^ 0xffffffff;
}

fs.mkdirSync(outDir, { recursive: true });
for (const [ten, S] of [["tray.png", 32], ["tray@2x.png", 64], ["icon.png", 256]]) {
  fs.writeFileSync(path.join(outDir, ten), vePng(S));
  console.log("đã tạo", path.join("assets", ten), `(${S}×${S})`);
}
