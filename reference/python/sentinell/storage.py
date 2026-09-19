"""Lưu trữ cục bộ trên máy — khóa, danh bạ (khóa đã ghim), và lịch sử tin nhắn.

Đáp ứng tiêu chí "app lưu trữ cục bộ trên PC" và "quản lý khóa (tạo, đổi khóa)":
  - Khóa danh tính lưu trong tệp `identity.json` trên đĩa của thiết bị.
  - Lịch sử tin nhắn lưu trong SQLite `messages.db`, **mã hóa khi lưu (at-rest)** bằng
    AES-256-GCM với khóa lưu trữ cục bộ → mở tệp .db ra chỉ thấy bản mã.
  - Danh bạ `contacts.json` giữ khóa công khai của peer đã GHIM qua QR (out-of-band),
    dùng để chống mạo danh khi bắt tay.

Mỗi node có một thư mục dữ liệu riêng (mặc định ./data, đổi qua biến môi trường
SENTINELL_DATA) — nhờ đó chạy 2 node trên cùng một máy để thử nghiệm cũng tách biệt.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import crypto


class Storage:
    def __init__(self, data_dir: str | os.PathLike) -> None:
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.identity_path = self.dir / "identity.json"
        self.contacts_path = self.dir / "contacts.json"
        self.db_path = self.dir / "messages.db"
        self._load_identity()
        self._load_contacts()
        self._init_db()

    # ---------------------- Danh tính & khóa ----------------------
    def _load_identity(self) -> None:
        if self.identity_path.exists():
            self.identity = json.loads(self.identity_path.read_text(encoding="utf-8"))
        else:
            priv, pub = crypto.gen_keypair()
            self.identity = {
                "priv": priv,
                "pub": pub,
                "name": f"Thiết bị {crypto.fingerprint(pub)[:6]}",
                "created": time.time(),
                "storage_key": os.urandom(32).hex(),
                "archived": [],  # các khóa công khai cũ sau khi xoay
            }
            self._save_identity()

    def _save_identity(self) -> None:
        self.identity_path.write_text(
            json.dumps(self.identity, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    @property
    def id_priv(self) -> str:
        return self.identity["priv"]

    @property
    def id_pub(self) -> str:
        return self.identity["pub"]

    @property
    def name(self) -> str:
        return self.identity["name"]

    def set_name(self, name: str) -> None:
        self.identity["name"] = name.strip() or self.identity["name"]
        self._save_identity()

    def rotate_identity(self) -> dict:
        """Đổi (xoay) khóa danh tính: lưu khóa cũ vào 'archived', sinh khóa mới.

        Giữ nguyên storage_key để vẫn giải mã được lịch sử cũ. Sau khi xoay, các
        liên hệ cần quét lại QR để ghim khóa mới (vì fingerprint đã thay đổi)."""
        self.identity["archived"].append(
            {"pub": self.identity["pub"], "retired": time.time()}
        )
        priv, pub = crypto.gen_keypair()
        self.identity["priv"] = priv
        self.identity["pub"] = pub
        self.identity["created"] = time.time()
        self._save_identity()
        return {"pub": pub, "fingerprint": crypto.fingerprint(pub)}

    def export_public(self) -> dict:
        """Dữ liệu công khai để trao đổi qua QR."""
        return {"k": self.id_pub, "n": self.name, "fp": crypto.fingerprint(self.id_pub)}

    def export_backup(self) -> dict:
        """Sao lưu TOÀN BỘ danh tính (gồm khóa bí mật) — chỉ để người dùng tự giữ."""
        return dict(self.identity)

    def import_backup(self, data: dict) -> None:
        for key in ("priv", "pub", "storage_key"):
            if key not in data:
                raise ValueError("Tệp sao lưu không hợp lệ")
        self.identity = {
            "priv": data["priv"], "pub": data["pub"],
            "name": data.get("name", self.identity["name"]),
            "created": data.get("created", time.time()),
            "storage_key": data["storage_key"],
            "archived": data.get("archived", []),
        }
        self._save_identity()

    # ---------------------- Danh bạ (khóa đã ghim) ----------------------
    def _load_contacts(self) -> None:
        if self.contacts_path.exists():
            self.contacts = json.loads(self.contacts_path.read_text(encoding="utf-8"))
        else:
            self.contacts = {}

    def _save_contacts(self) -> None:
        self.contacts_path.write_text(
            json.dumps(self.contacts, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def pin_contact(self, pub: str, name: str = "") -> dict:
        """Ghim khóa công khai của một peer (lấy được qua QR out-of-band)."""
        fp = crypto.fingerprint(pub)
        self.contacts[fp] = {
            "pub": pub,
            "name": name or self.contacts.get(fp, {}).get("name", f"Liên hệ {fp[:6]}"),
            "pinned_at": time.time(),
        }
        self._save_contacts()
        return self.contacts[fp]

    def contact_by_pub(self, pub: str) -> dict | None:
        return self.contacts.get(crypto.fingerprint(pub))

    def list_contacts(self) -> list[dict]:
        return [{"fingerprint": fp, **c} for fp, c in self.contacts.items()]

    # ---------------------- Tin nhắn (mã hóa at-rest) ----------------------
    def _init_db(self) -> None:
        self.db = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS messages(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   peer_pub TEXT, direction TEXT, ts REAL,
                   nonce BLOB, body_ct BLOB)"""
        )
        self.db.commit()

    def _skey(self) -> bytes:
        return bytes.fromhex(self.identity["storage_key"])

    def save_message(self, peer_pub: str, direction: str, body: dict, ts: float | None = None) -> float:
        ts = ts if ts is not None else time.time()
        nonce = os.urandom(12)
        pt = json.dumps(body, ensure_ascii=False).encode()
        ct = AESGCM(self._skey()).encrypt(nonce, pt, None)  # mã hóa khi lưu
        self.db.execute(
            "INSERT INTO messages(peer_pub,direction,ts,nonce,body_ct) VALUES(?,?,?,?,?)",
            (peer_pub, direction, ts, nonce, ct),
        )
        self.db.commit()
        return ts

    def load_history(self, peer_pub: str, limit: int = 200) -> list[dict]:
        cur = self.db.execute(
            "SELECT direction,ts,nonce,body_ct FROM messages WHERE peer_pub=? ORDER BY id DESC LIMIT ?",
            (peer_pub, limit),
        )
        rows = cur.fetchall()
        out = []
        skey = self._skey()
        for direction, ts, nonce, ct in reversed(rows):
            try:
                body = json.loads(AESGCM(skey).decrypt(bytes(nonce), bytes(ct), None).decode())
            except Exception:
                body = {"type": "text", "text": "<không giải mã được lịch sử>"}
            out.append({"direction": direction, "ts": ts, "body": body})
        return out

    def clear_history(self, peer_pub: str) -> None:
        self.db.execute("DELETE FROM messages WHERE peer_pub=?", (peer_pub,))
        self.db.commit()
