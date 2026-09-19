"""Bước 1/3 test interop: bản tham chiếu Python sinh bộ vector cố định.

Chạy handshake + 1 tin nhắn với khóa/nonce CỐ ĐỊNH rồi ghi ra scripts/vectors.json để
bản JavaScript (core/protocol.js) kiểm chứng lại: cùng transcript, cùng khóa dẫn xuất,
cùng safety number, xác minh được chữ ký DER của Python, giải mã được bản mã của Python.
"""
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

# Khóa & nonce cố định (sinh một lần bằng gen_keypair rồi ghim lại để vector ổn định)
ID_A = crypto.gen_keypair()
ID_B = crypto.gen_keypair()
EPH_A = crypto.gen_keypair()
EPH_B = crypto.gen_keypair()
NONCE_A = "a1" * 16
NONCE_B = "b2" * 16

A = crypto.Session("I", ID_A[0], ID_A[1], "Alice")
B = crypto.Session("R", ID_B[0], ID_B[1], "Bob")
A.eph_priv, A.eph_pub, A.nonce = EPH_A[0], EPH_A[1], NONCE_A
B.eph_priv, B.eph_pub, B.nonce = EPH_B[0], EPH_B[1], NONCE_B

hi, hr = A.hello(), B.hello()
sig_b = B.on_hello(hi)
sig_a = A.on_hello(hr)
A.on_sig(sig_b, pinned_pub=ID_B[1])
B.on_sig(sig_a, pinned_pub=ID_A[1])
assert A.ready and B.ready and A.trusted and B.trusted

msg = A.encrypt("text", {"text": "vector"})   # seq 0, chiều I→R

out = {
    "id_a": {"priv": ID_A[0], "pub": ID_A[1]},
    "id_b": {"priv": ID_B[0], "pub": ID_B[1]},
    "eph_a": {"priv": EPH_A[0], "pub": EPH_A[1]},
    "eph_b": {"priv": EPH_B[0], "pub": EPH_B[1]},
    "nonce_a": NONCE_A,
    "nonce_b": NONCE_B,
    "transcript_sha256": crypto.sha256(A._transcript()).hex(),
    "sig_a_der": sig_a["sig"],
    "sig_b_der": sig_b["sig"],
    "a_send_ck_after_msg0": A.send_ck.hex(),   # sau khi ratchet 1 bước
    "a_recv_ck": A.recv_ck.hex(),
    "safety": A.safety,
    "fp_a": crypto.fingerprint(ID_A[1]),
    "fp_b": crypto.fingerprint(ID_B[1]),
    "msg0_from_a": msg,
}
(Path(__file__).parent / "vectors.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
print("[python] đã sinh scripts/vectors.json")
