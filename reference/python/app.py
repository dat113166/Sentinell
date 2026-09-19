"""Sentinell — điểm khởi động app node trên một thiết bị.

    python app.py                 # cổng 8000, dữ liệu ./data
    python app.py --port 8001 --data ./data-b     # chạy node thứ hai (để thử trên 1 máy)

Biến môi trường tương đương: SENTINELL_PORT, SENTINELL_DATA.
"""
from __future__ import annotations

import argparse
import io
import os
import socket
import sys

# Console Windows mặc định cp1252 — ép UTF-8 để in tiếng Việt + QR.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

import uvicorn

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sentinell.node import Node, create_app
from sentinell.discovery import local_ip
from sentinell.crypto import fingerprint

try:
    import qrcode
except ImportError:
    qrcode = None


def print_banner(node: Node, port: int) -> None:
    ip = local_ip()
    line = "=" * 62
    print("\n" + line)
    print("  SENTINELL — nhắn tin bảo mật P2P giữa 2 thiết bị (mô hình node)")
    print(line)
    print(f"  Mở giao diện trên MÁY NÀY:   http://127.0.0.1:{port}/")
    print(f"  (Địa chỉ LAN của máy này:    {ip}:{port})")
    print(f"  Tên thiết bị:  {node.storage.name}")
    print(f"  Vân tay khóa:  {fingerprint(node.storage.id_pub)}")
    print(line)
    print("  • Hai máy cùng LAN/hotspot sẽ TỰ THẤY nhau (mDNS) — không cần gõ IP.")
    print("  • Quét QR trên giao diện để GHIM khóa nhau (chống mạo danh).")
    print("  • Tin nhắn & khóa lưu cục bộ (đã mã hóa) trong thư mục dữ liệu.")
    if qrcode is not None:
        qr = qrcode.QRCode(border=1)
        qr.add_data(f"http://{ip}:{port}/")
        qr.make(fit=True)
        buf = io.StringIO()
        qr.print_ascii(out=buf, invert=True)
        print(line)
        print("  (QR mở nhanh giao diện trên máy này nếu cần):\n")
        print(buf.getvalue())
    print(line + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("SENTINELL_PORT", "8000")))
    ap.add_argument("--data", default=os.environ.get("SENTINELL_DATA", "./data"))
    args = ap.parse_args()

    node = Node(args.data, args.port)
    app = create_app(node)
    print_banner(node, args.port)
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
