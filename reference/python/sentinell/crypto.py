"""Lõi mật mã của Sentinell — chạy trong node Python ở CẢ HAI thiết bị.

Vì cả hai đầu đều là node Python nên chỉ cần hai bên thống nhất với nhau; không
còn ràng buộc parity với JavaScript. Toàn bộ dùng thư viện `cryptography` đã kiểm
định (đúng khuyến cáo mục 4.8 bài giảng: không tự cài đặt lại phép toán mật mã).

Ánh xạ lý thuyết (xem docs/BAOCAO.md):
  - Danh tính     : cặp khóa ECDSA P-256 (chữ ký số, Chương 3) — thay vai trò chứng thư.
  - Bắt tay       : ECDH tạm thời (ephemeral → forward secrecy, mục 4.4) + ký transcript
                    bằng ECDSA (chống kẻ đứng giữa, mục 4.5).
  - Dẫn xuất khóa : HKDF-SHA256 (mục 4.1.3).
  - Mã hóa        : AES-256-GCM (mã hóa kèm xác thực, giáo trình 2.6.5).
  - Ratchet       : mỗi tin nhắn một khóa mới, xóa sau khi dùng (forward secrecy, mục 4.10).
  - Safety number : SHA-256 hai khóa danh tính → đối chiếu ngoài kênh (mục 4.5). Ở đây còn
                    được củng cố bằng việc GHIM khóa qua QR (out-of-band).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CURVE = ec.SECP256R1()
ROOT_INFO = b"sentinell-root-v2"
TRANSCRIPT_TAG = b"sentinell-hs-v2"


# --------------------------------------------------------------------------
# Tiện ích khóa / băm / HKDF / AES-GCM
# --------------------------------------------------------------------------
def gen_keypair() -> tuple[str, str]:
    """Sinh cặp khóa P-256. Trả về (priv_hex, pub_hex[nén 33 byte])."""
    priv = ec.generate_private_key(CURVE)
    priv_hex = priv.private_numbers().private_value.to_bytes(32, "big").hex()
    pub_hex = priv.public_key().public_bytes(
        Encoding.X962, PublicFormat.CompressedPoint
    ).hex()
    return priv_hex, pub_hex


def _load_priv(priv_hex: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int(priv_hex, 16), CURVE)


def _load_pub(pub_hex: str) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, bytes.fromhex(pub_hex))


def sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def sign(priv_hex: str, data: bytes) -> str:
    return _load_priv(priv_hex).sign(data, ec.ECDSA(hashes.SHA256())).hex()


def verify(pub_hex: str, sig_hex: str, data: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    try:
        _load_pub(pub_hex).verify(bytes.fromhex(sig_hex), data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def ecdh_x(priv_hex: str, peer_pub_hex: str) -> bytes:
    """Bí mật chung ECDH = tọa độ x (32 byte)."""
    return _load_priv(priv_hex).exchange(ec.ECDH(), _load_pub(peer_pub_hex))


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _seq_nonce(direction: int, seq: int) -> bytes:
    return bytes([direction & 0xFF]) + b"\x00" * 7 + seq.to_bytes(4, "big")


def fingerprint(pub_hex: str) -> str:
    """Vân tay ngắn của một khóa công khai để hiển thị/định danh."""
    return sha256(bytes.fromhex(pub_hex)).hex()[:16]


def safety_number(pub_a_hex: str, pub_b_hex: str) -> str:
    """60 chữ số (12 nhóm 5) từ SHA-256 của hai khóa danh tính, thứ tự cố định."""
    lo, hi = sorted([pub_a_hex, pub_b_hex])
    h1 = sha256(bytes.fromhex(lo) + bytes.fromhex(hi))
    h2 = sha256(h1)
    buf = h1 + h2
    groups = []
    for i in range(12):
        v = int.from_bytes(buf[i * 4:i * 4 + 4], "big")
        groups.append(str(v % 100000).zfill(5))
    return " ".join(groups)


# --------------------------------------------------------------------------
# Phiên bảo mật (state machine bắt tay + mã hóa/giải mã)
# --------------------------------------------------------------------------
@dataclass
class Session:
    """Một phiên giữa node này và một peer.

    role: "I" (initiator, bên chủ động kết nối) hoặc "R" (responder).
    """
    role: str
    id_priv: str
    id_pub: str
    display_name: str = "?"
    on_log: object = None  # callable(step:str, detail:str)

    eph_priv: str = field(default="", init=False)
    eph_pub: str = field(default="", init=False)
    nonce: str = field(default="", init=False)
    peer: dict = field(default_factory=dict, init=False)
    ready: bool = field(default=False, init=False)
    auth_failed: bool = field(default=False, init=False)
    trusted: bool = field(default=False, init=False)  # khóa peer đã được ghim (QR) chưa
    send_ck: bytes = field(default=b"", init=False)
    recv_ck: bytes = field(default=b"", init=False)
    send_seq: int = field(default=0, init=False)
    recv_seq: int = field(default=0, init=False)
    safety: str = field(default="", init=False)

    def __post_init__(self) -> None:
        import os
        self.eph_priv, self.eph_pub = gen_keypair()
        self.nonce = os.urandom(16).hex()

    def _log(self, step: str, detail: str) -> None:
        if self.on_log:
            self.on_log(step, detail)

    @property
    def dir(self) -> int:
        return 0 if self.role == "I" else 1

    # ---- Gói handshake đầu tiên ----
    def hello(self) -> dict:
        self._log("hs-send", f"Gửi handshake: id={self.id_pub[:16]}… eph={self.eph_pub[:16]}… nonce={self.nonce[:12]}…")
        return {
            "type": "hs",
            "id_pub": self.id_pub,
            "eph_pub": self.eph_pub,
            "nonce": self.nonce,
            "name": self.display_name,
        }

    def _transcript(self) -> bytes:
        me = {"id": self.id_pub, "eph": self.eph_pub, "nonce": self.nonce}
        them = {"id": self.peer["id_pub"], "eph": self.peer["eph_pub"], "nonce": self.peer["nonce"]}
        I, R = (me, them) if self.role == "I" else (them, me)
        parts = [TRANSCRIPT_TAG]
        for p in (I, R):
            parts += [bytes.fromhex(p["id"]), bytes.fromhex(p["eph"]), bytes.fromhex(p["nonce"])]
        return b"".join(parts)

    # ---- Nhận handshake của peer → trả về gói chữ ký ----
    def on_hello(self, data: dict) -> dict:
        self.peer = {"id_pub": data["id_pub"], "eph_pub": data["eph_pub"],
                     "nonce": data["nonce"], "name": data.get("name", "?")}
        self._log("hs-recv", f"Nhận handshake của {self.peer['name']}: id={data['id_pub'][:16]}…")
        h = sha256(self._transcript())
        sig = sign(self.id_priv, h)
        self._log("sign", f"Ký transcript (SHA-256) bằng ECDSA: {sig[:24]}…")
        return {"type": "hs-sig", "sig": sig}

    # ---- Nhận chữ ký của peer → xác minh + dẫn xuất khóa ----
    def on_sig(self, data: dict, pinned_pub: str | None = None) -> None:
        h = sha256(self._transcript())
        ok = verify(self.peer["id_pub"], data["sig"], h)
        if not ok:
            self.auth_failed = True
            self._log("verify-fail", "❌ Chữ ký peer KHÔNG hợp lệ — nghi ngờ kẻ đứng giữa! Hủy bắt tay.")
            return
        # Nếu đã ghim khóa peer qua QR và khớp → tin cậy tuyệt đối (out-of-band).
        if pinned_pub is not None:
            if pinned_pub == self.peer["id_pub"]:
                self.trusted = True
                self._log("verify-ok", "✅ Chữ ký hợp lệ và khóa KHỚP khóa đã ghim qua QR — tin cậy.")
            else:
                self.auth_failed = True
                self._log("verify-fail", "❌ Chữ ký hợp lệ nhưng khóa KHÁC khóa đã ghim qua QR — có thể bị mạo danh!")
                return
        else:
            self._log("verify-ok", "✅ Chữ ký hợp lệ (chưa ghim khóa — nên quét QR để xác minh out-of-band).")

        x = ecdh_x(self.eph_priv, self.peer["eph_pub"])
        nonce_i = self.nonce if self.role == "I" else self.peer["nonce"]
        nonce_r = self.peer["nonce"] if self.role == "I" else self.nonce
        salt = bytes.fromhex(nonce_i) + bytes.fromhex(nonce_r)
        okm = _hkdf(x, salt, ROOT_INFO, 64)
        ck_i2r, ck_r2i = okm[:32], okm[32:]
        if self.role == "I":
            self.send_ck, self.recv_ck = ck_i2r, ck_r2i
        else:
            self.send_ck, self.recv_ck = ck_r2i, ck_i2r
        self.ready = True
        self.safety = safety_number(self.id_pub, self.peer["id_pub"])
        self._log("derive", "ECDH→x, HKDF→root(64B), tách 2 chain key theo chiều. Sẵn sàng.")
        self._log("safety", f"Safety number: {self.safety}")

    # ---- Mã hóa một thông điệp ----
    def encrypt(self, msg_type: str, obj: dict) -> dict:
        if not self.ready:
            raise RuntimeError("Phiên chưa sẵn sàng")
        seq = self.send_seq
        self.send_seq += 1
        mk = _hkdf(self.send_ck, b"", b"sentinell-msg")
        self.send_ck = _hkdf(self.send_ck, b"", b"sentinell-chain")
        header = {"seq": seq, "dir": self.dir, "type": msg_type}
        aad = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode()
        nonce = _seq_nonce(self.dir, seq)
        plaintext = json.dumps({"type": msg_type, **obj}, ensure_ascii=False).encode()
        ct = AESGCM(mk).encrypt(nonce, plaintext, aad).hex()
        self._log("encrypt", f"AES-256-GCM (khóa ratchet seq={seq}) → {ct[:24]}…  | chain key tiến 1 bước")
        return {"type": "msg", "seq": seq, "dir": self.dir, "mtype": msg_type, "ct": ct}

    # ---- Giải mã một thông điệp ----
    def decrypt(self, payload: dict) -> dict:
        seq = payload["seq"]
        if seq != self.recv_seq:
            self._log("warn", f"⚠️ seq nhận ({seq}) lệch dự kiến ({self.recv_seq}) — có thể chèn/lặp/rớt gói.")
        mk = _hkdf(self.recv_ck, b"", b"sentinell-msg")
        self.recv_ck = _hkdf(self.recv_ck, b"", b"sentinell-chain")
        self.recv_seq = seq + 1
        header = {"seq": seq, "dir": payload["dir"], "type": payload["mtype"]}
        aad = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode()
        nonce = _seq_nonce(payload["dir"], seq)
        try:
            pt = AESGCM(mk).decrypt(nonce, bytes.fromhex(payload["ct"]), aad)
        except Exception:
            self._log("decrypt-fail", f"❌ GCM từ chối giải mã seq={seq} — bản mã bị sửa hoặc khóa sai (toàn vẹn hỏng).")
            raise
        self._log("decrypt", f"Giải mã + kiểm toàn vẹn GCM seq={seq} OK")
        return json.loads(pt.decode())
