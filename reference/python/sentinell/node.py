"""Node Sentinell — app đứng độc lập chạy trên mỗi thiết bị.

Một tiến trình duy nhất đảm nhận:
  • Phục vụ giao diện (thin-client) ở localhost  -> secure context, camera quét QR chạy được.
  • Điểm cuối `/ui`  : WebSocket nói chuyện với giao diện trên chính máy này.
  • Điểm cuối `/peer`: WebSocket nhận kết nối P2P TỪ node của thiết bị kia.
  • Kết nối ra `/peer` của thiết bị kia (đóng vai initiator).
  • Tìm thiết bị trên LAN qua mDNS (discovery.py).
  • Lưu khóa + tin nhắn cục bộ đã mã hóa (storage.py).

Mật mã (crypto.py) chạy ngay trong node ở CẢ HAI thiết bị, nên node là "đầu cuối"
thực sự: dữ liệu rời máy đã là bản mã.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import websockets

from . import crypto
from .discovery import Discovery, local_ip
from .storage import Storage

# web/ nằm ở gốc repo (reference/python/sentinell/node.py -> lên 3 cấp)
WEB_DIR = Path(__file__).resolve().parents[3] / "web"
CHUNK = 48 * 1024


class _WS:
    """Bọc đồng nhất WebSocket phía server (FastAPI) và phía client (websockets)."""

    def __init__(self, ws, kind: str) -> None:
        self.ws = ws
        self.kind = kind  # "server" | "client"

    async def send_json(self, obj: dict) -> None:
        if self.kind == "server":
            await self.ws.send_json(obj)
        else:
            await self.ws.send(json.dumps(obj))

    async def recv_json(self) -> dict:
        if self.kind == "server":
            return await self.ws.receive_json()
        return json.loads(await self.ws.recv())

    async def close(self) -> None:
        try:
            await self.ws.close()
        except Exception:
            pass


class Node:
    def __init__(self, data_dir: str, port: int) -> None:
        self.storage = Storage(data_dir)
        self.port = port
        self.node_id = secrets.token_hex(6)
        self.files_dir = Path(data_dir) / "files"
        self.files_dir.mkdir(exist_ok=True)

        self.ui_clients: set[WebSocket] = set()
        self.discovery: Discovery | None = None
        self.peers: list[dict] = []

        # phiên P2P hiện hành (mỗi lúc 1 peer cho gọn)
        self.session: crypto.Session | None = None
        self.peer_ws: _WS | None = None
        self.peer_meta: dict = {}
        self.expect_pub: str | None = None
        self._incoming_files: dict = {}

    # ------------------------------------------------------------------ UI
    async def ui_broadcast(self, obj: dict) -> None:
        dead = []
        for ws in self.ui_clients:
            try:
                await ws.send_json(obj)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.ui_clients.discard(ws)

    def _session_log(self, step: str, detail: str) -> None:
        asyncio.create_task(self.ui_broadcast({"type": "log", "step": step, "detail": detail}))

    def state(self) -> dict:
        conn = None
        if self.session and self.session.ready:
            conn = {
                "connected": True,
                "peer_name": self.peer_meta.get("name", "?"),
                "peer_pub": self.session.peer["id_pub"],
                "peer_fp": crypto.fingerprint(self.session.peer["id_pub"]),
                "trusted": self.session.trusted,
                "safety": self.session.safety,
            }
        return {
            "type": "state",
            "identity": {
                "pub": self.storage.id_pub,
                "fp": crypto.fingerprint(self.storage.id_pub),
                "name": self.storage.name,
                "created": self.storage.identity["created"],
                "archived": len(self.storage.identity["archived"]),
            },
            "contacts": self.storage.list_contacts(),
            "peers": self.peers,
            "connection": conn,
        }

    async def push_state(self) -> None:
        await self.ui_broadcast(self.state())

    # ------------------------------------------------------------ discovery
    async def start_discovery(self) -> None:
        self.discovery = Discovery(
            self.node_id, self.storage.name, crypto.fingerprint(self.storage.id_pub),
            self.port, self._on_peers,
        )
        # kèm khóa công khai vào quảng bá để tiện hiển thị (nhưng chỉ tin khi đã ghim QR)
        await self.discovery.start()
        await self.discovery.update_props_pub(self.storage.id_pub)

    def _on_peers(self, peers: list[dict]) -> None:
        self.peers = peers
        asyncio.create_task(self.ui_broadcast({"type": "peers", "peers": peers}))

    # --------------------------------------------------------- xử lý lệnh UI
    async def handle_ui(self, cmd: dict) -> None:
        t = cmd.get("cmd")
        if t == "get_state":
            await self.push_state()
        elif t == "set_name":
            self.storage.set_name(cmd.get("name", ""))
            if self.discovery:
                await self.discovery.update_name(self.storage.name)
            await self.push_state()
        elif t == "rotate_key":
            self.storage.rotate_identity()
            if self.discovery:
                await self.discovery.update_props(self.storage.name,
                                                  crypto.fingerprint(self.storage.id_pub),
                                                  self.storage.id_pub)
            await self.ui_broadcast({"type": "notice", "text": "Đã xoay khóa danh tính. Liên hệ cần quét lại QR của bạn."})
            await self.push_state()
        elif t == "pin_key":
            c = self.storage.pin_contact(cmd["pub"], cmd.get("name", ""))
            await self.ui_broadcast({"type": "notice", "text": f"Đã ghim khóa của {c['name']} (vân tay {crypto.fingerprint(cmd['pub'])[:8]}…)."})
            await self.push_state()
        elif t == "connect":
            asyncio.create_task(self.connect_peer(cmd["host"], int(cmd["port"]), cmd.get("expect_pub")))
        elif t == "disconnect":
            await self._teardown_peer("Bạn đã ngắt kết nối.")
        elif t == "send_text":
            await self.send_text(cmd.get("text", ""))
        elif t == "send_file":
            await self.send_file(cmd["name"], cmd.get("mime", ""), cmd["data_b64"])
        elif t == "load_history":
            hist = self.storage.load_history(cmd["peer_pub"])
            await self.ui_broadcast({"type": "history", "peer_pub": cmd["peer_pub"], "items": hist})
        elif t == "get_backup":
            await self.ui_broadcast({"type": "backup", "data": self.storage.export_backup()})
        elif t == "import_backup":
            self.storage.import_backup(cmd["data"])
            if self.discovery:
                await self.discovery.update_props(self.storage.name,
                                                  crypto.fingerprint(self.storage.id_pub),
                                                  self.storage.id_pub)
            await self.ui_broadcast({"type": "notice", "text": "Đã phục hồi danh tính từ bản sao lưu."})
            await self.push_state()

    # ------------------------------------------------------- kết nối peer
    async def connect_peer(self, host: str, port: int, expect_pub: str | None) -> None:
        if self.session is not None:
            await self._teardown_peer("Chuyển sang kết nối mới.")
        self.expect_pub = expect_pub
        try:
            ws = await websockets.connect(f"ws://{host}:{port}/peer", max_size=8 * 1024 * 1024)
        except Exception as exc:
            await self.ui_broadcast({"type": "notice", "text": f"Không kết nối được {host}:{port} ({exc})", "bad": True})
            return
        await self.peer_loop(_WS(ws, "client"), "I", expect_pub)

    async def peer_loop(self, ws: _WS, role: str, expect_pub: str | None) -> None:
        self.session = crypto.Session(role, self.storage.id_priv, self.storage.id_pub,
                                      self.storage.name, on_log=self._session_log)
        self.peer_ws = ws
        self._incoming_files = {}
        try:
            await ws.send_json(self.session.hello())
            while True:
                msg = await ws.recv_json()
                if not await self._handle_peer_msg(msg, expect_pub):
                    break
        except (WebSocketDisconnect, websockets.ConnectionClosed):
            pass
        except Exception as exc:
            await self.ui_broadcast({"type": "notice", "text": f"Lỗi kết nối peer: {exc}", "bad": True})
        finally:
            await self._teardown_peer("Đối phương đã ngắt kết nối.", silent_if_none=True)

    async def _handle_peer_msg(self, msg: dict, expect_pub: str | None) -> bool:
        s = self.session
        if s is None:
            return False
        t = msg.get("type")
        if t == "hs":
            self.peer_meta = {"name": msg.get("name", "?")}
            sig = s.on_hello(msg)
            await self.peer_ws.send_json(sig)
            return True
        if t == "hs-sig":
            # Xác định khóa kỳ vọng: initiator dùng expect_pub; responder tra danh bạ đã ghim.
            pinned = expect_pub
            if pinned is None:
                c = self.storage.contact_by_pub(s.peer["id_pub"])
                pinned = c["pub"] if c else None
            s.on_sig(msg, pinned_pub=pinned)
            if s.auth_failed:
                await self.ui_broadcast({"type": "notice", "text": "❌ Xác thực thất bại — nghi ngờ kẻ đứng giữa / mạo danh. Đã hủy.", "bad": True})
                await self.push_state()
                return False
            # kết nối thành công
            await self.ui_broadcast({"type": "connected", "connection": self.state()["connection"]})
            hist = self.storage.load_history(s.peer["id_pub"])
            await self.ui_broadcast({"type": "history", "peer_pub": s.peer["id_pub"], "items": hist})
            await self.push_state()
            return True
        if t == "msg":
            try:
                obj = s.decrypt(msg)
            except Exception:
                await self.ui_broadcast({"type": "notice", "text": "Một tin đến không giải mã được (toàn vẹn hỏng).", "bad": True})
                return True
            await self._on_plain_incoming(obj)
            return True
        return True

    async def _on_plain_incoming(self, obj: dict) -> None:
        s = self.session
        peer_pub = s.peer["id_pub"]
        mtype = obj.get("type")
        if mtype == "text":
            ts = self.storage.save_message(peer_pub, "in", obj)
            await self.ui_broadcast({"type": "message", "direction": "in", "ts": ts, "body": obj})
        elif mtype == "file-meta":
            self._incoming_files[obj["name"]] = {"meta": obj, "chunks": [None] * obj["chunks"], "recv": 0}
            await self.ui_broadcast({"type": "notice", "text": f"Đang nhận tệp \"{obj['name']}\"…"})
        elif mtype == "file-chunk":
            ent = self._incoming_files.get(obj["name"])
            if not ent:
                return
            ent["chunks"][obj["idx"]] = base64.b64decode(obj["data"])
            ent["recv"] += 1
            if ent["recv"] == ent["meta"]["chunks"]:
                await self._assemble_file(ent, peer_pub)
                self._incoming_files.pop(obj["name"], None)

    async def _assemble_file(self, ent: dict, peer_pub: str) -> None:
        data = b"".join(ent["chunks"])
        meta = ent["meta"]
        ok = hashlib.sha256(data).hexdigest() == meta["hash"]
        safe = os.path.basename(meta["name"]).replace("..", "_")
        out = self.files_dir / f"{secrets.token_hex(4)}_{safe}"
        out.write_bytes(data)
        body = {"type": "file", "name": meta["name"], "size": meta["size"],
                "mime": meta.get("mime", ""), "url": f"/file/{out.name}", "integrity": ok}
        ts = self.storage.save_message(peer_pub, "in", body)
        await self.ui_broadcast({"type": "message", "direction": "in", "ts": ts, "body": body})

    async def send_text(self, text: str) -> None:
        text = text.strip()
        if not text or not (self.session and self.session.ready):
            return
        payload = self.session.encrypt("text", {"text": text})
        await self.peer_ws.send_json(payload)
        body = {"type": "text", "text": text}
        ts = self.storage.save_message(self.session.peer["id_pub"], "out", body)
        await self.ui_broadcast({"type": "message", "direction": "out", "ts": ts, "body": body})

    async def send_file(self, name: str, mime: str, data_b64: str) -> None:
        if not (self.session and self.session.ready):
            return
        data = base64.b64decode(data_b64)
        digest = hashlib.sha256(data).hexdigest()
        nchunks = max(1, (len(data) + CHUNK - 1) // CHUNK)
        await self.peer_ws.send_json(self.session.encrypt(
            "file-meta", {"name": name, "size": len(data), "mime": mime, "hash": digest, "chunks": nchunks}))
        for i in range(nchunks):
            chunk = data[i * CHUNK:(i + 1) * CHUNK]
            await self.peer_ws.send_json(self.session.encrypt(
                "file-chunk", {"name": name, "idx": i, "data": base64.b64encode(chunk).decode()}))
        # lưu bản gửi + phục vụ lại chính mình
        safe = os.path.basename(name).replace("..", "_")
        out = self.files_dir / f"{secrets.token_hex(4)}_{safe}"
        out.write_bytes(data)
        body = {"type": "file", "name": name, "size": len(data), "mime": mime,
                "url": f"/file/{out.name}", "integrity": True}
        ts = self.storage.save_message(self.session.peer["id_pub"], "out", body)
        await self.ui_broadcast({"type": "message", "direction": "out", "ts": ts, "body": body})

    async def _teardown_peer(self, reason: str, silent_if_none: bool = False) -> None:
        had = self.session is not None
        if self.peer_ws:
            await self.peer_ws.close()
        self.session = None
        self.peer_ws = None
        self.peer_meta = {}
        self._incoming_files = {}
        if had or not silent_if_none:
            await self.ui_broadcast({"type": "disconnected", "reason": reason})
            await self.push_state()


# ============================================================ FastAPI wiring
def create_app(node: Node) -> FastAPI:
    app = FastAPI(title="Sentinell node")

    @app.get("/file/{name}")
    async def get_file(name: str):
        p = node.files_dir / name
        if not p.exists():
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(str(p))

    @app.websocket("/ui")
    async def ws_ui(ws: WebSocket):
        await ws.accept()
        node.ui_clients.add(ws)
        await ws.send_json(node.state())
        try:
            while True:
                cmd = await ws.receive_json()
                await node.handle_ui(cmd)
        except WebSocketDisconnect:
            pass
        finally:
            node.ui_clients.discard(ws)

    @app.websocket("/peer")
    async def ws_peer(ws: WebSocket):
        await ws.accept()
        if node.session is not None:
            await ws.send_json({"type": "busy"})
            await ws.close()
            return
        await node.peer_loop(_WS(ws, "server"), "R", None)

    @app.on_event("startup")
    async def _startup():
        await node.start_discovery()

    @app.on_event("shutdown")
    async def _shutdown():
        if node.discovery:
            await node.discovery.stop()

    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
    return app
