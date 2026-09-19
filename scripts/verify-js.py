"""Bước 3/3 test interop: Python xác minh chữ ký và giải mã bản mã do JavaScript sinh."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "reference" / "python"))
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from sentinell import crypto  # noqa: E402

V = json.loads((Path(__file__).parent / "vectors.json").read_text(encoding="utf-8"))
J = json.loads((Path(__file__).parent / "js-out.json").read_text(encoding="utf-8"))

fails = 0
def check(name: str, ok: bool) -> None:
    global fails
    print(f"  {'✓' if ok else '✗'} {name}")
    if not ok:
        fails += 1

h = bytes.fromhex(V["transcript_sha256"])
print("[python] kiểm chứng đầu ra của JS:")
check("Python xác minh chữ ký DER của JS (A)", crypto.verify(V["id_a"]["pub"], J["sig_a_der_js"], h))
check("Python xác minh chữ ký DER của JS (B)", crypto.verify(V["id_b"]["pub"], J["sig_b_der_js"], h))

# Dựng lại B (Python) đúng trạng thái sau bắt tay để giải mã tin của JS A
A = crypto.Session("I", V["id_a"]["priv"], V["id_a"]["pub"], "Alice")
B = crypto.Session("R", V["id_b"]["priv"], V["id_b"]["pub"], "Bob")
A.eph_priv, A.eph_pub, A.nonce = V["eph_a"]["priv"], V["eph_a"]["pub"], V["nonce_a"]
B.eph_priv, B.eph_pub, B.nonce = V["eph_b"]["priv"], V["eph_b"]["pub"], V["nonce_b"]
B.on_hello(A.hello()); A.on_hello(B.hello())
B.on_sig({"sig": J["sig_a_der_js"]}, pinned_pub=V["id_a"]["pub"])
check("Python B bắt tay xong bằng chữ ký của JS", B.ready and B.trusted)
try:
    dec = B.decrypt(J["msg0_from_a_js"])
    check("Python B giải mã được bản mã của JS A", dec.get("text") == "vector-js")
except Exception as exc:
    check(f"Python B giải mã được bản mã của JS A ({exc})", False)

print(f"[python] {'TẤT CẢ ĐẠT' if fails == 0 else str(fails) + ' lỗi'}")
sys.exit(1 if fails else 0)
