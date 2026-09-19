"""Tìm kiếm thiết bị trên mạng LAN bằng mDNS/DNS-SD (thư viện zeroconf).

Đáp ứng tiêu chí "tìm kiếm trên mạng LAN": mỗi node tự QUẢNG BÁ dịch vụ
`_sentinell._tcp.local.` kèm tên + vân tay khóa, đồng thời DUYỆT để phát hiện các
node khác đang online — không cần gõ IP tay. Đây là cơ chế Bonjour/Avahi mà nhiều
ứng dụng LAN dùng.
"""
from __future__ import annotations

import asyncio
import socket

from zeroconf import ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

SERVICE_TYPE = "_sentinell._tcp.local."


def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


class Discovery:
    """Quảng bá node này và theo dõi các node khác trên LAN.

    on_change(peers: list[dict]) được gọi mỗi khi danh sách peer thay đổi.
    Mỗi peer: {id, name, fp, host, port}.
    """

    def __init__(self, node_id: str, name: str, fp: str, port: int, on_change) -> None:
        self.node_id = node_id
        self.name = name
        self.fp = fp
        self.port = port
        self.on_change = on_change
        self.ip = local_ip()
        self.peers: dict[str, dict] = {}
        self._aiozc: AsyncZeroconf | None = None
        self._browser: AsyncServiceBrowser | None = None
        self._info: AsyncServiceInfo | None = None
        # tên dịch vụ phải là duy nhất -> gắn node_id
        self._service_name = f"sentinell-{node_id[:10]}.{SERVICE_TYPE}"

        self.pub = ""

    def _props(self) -> dict:
        p = {"id": self.node_id, "name": self.name, "fp": self.fp}
        if self.pub:
            p["pub"] = self.pub
        return p

    async def start(self) -> None:
        self._aiozc = AsyncZeroconf()
        self._info = AsyncServiceInfo(
            SERVICE_TYPE,
            self._service_name,
            addresses=[socket.inet_aton(self.ip)],
            port=self.port,
            properties=self._props(),
            server=f"sentinell-{self.node_id[:10]}.local.",
        )
        await self._aiozc.async_register_service(self._info)
        self._browser = AsyncServiceBrowser(
            self._aiozc.zeroconf, SERVICE_TYPE, handlers=[self._on_state_change]
        )

    async def _reregister(self) -> None:
        if not (self._aiozc and self._info):
            return
        self._info = AsyncServiceInfo(
            SERVICE_TYPE, self._service_name,
            addresses=[socket.inet_aton(self.ip)], port=self.port,
            properties=self._props(), server=f"sentinell-{self.node_id[:10]}.local.",
        )
        try:
            await self._aiozc.async_update_service(self._info)
        except Exception:
            pass

    async def update_name(self, name: str) -> None:
        self.name = name
        await self._reregister()

    async def update_props(self, name: str, fp: str, pub: str) -> None:
        self.name, self.fp, self.pub = name, fp, pub
        await self._reregister()

    async def update_props_pub(self, pub: str) -> None:
        self.pub = pub
        await self._reregister()

    def _on_state_change(self, zeroconf, service_type, name, state_change) -> None:
        if name == self._service_name:
            return  # bỏ qua chính mình
        if state_change is ServiceStateChange.Removed:
            # tìm và xóa peer theo service name đã lưu
            for pid, p in list(self.peers.items()):
                if p.get("_sname") == name:
                    del self.peers[pid]
                    self._notify()
                    break
            return
        asyncio.ensure_future(self._resolve(name))

    async def _resolve(self, name: str) -> None:
        info = AsyncServiceInfo(SERVICE_TYPE, name)
        ok = await info.async_request(self._aiozc.zeroconf, 3000)
        if not ok:
            return
        props = {k.decode(): (v.decode() if v else "") for k, v in info.properties.items()}
        pid = props.get("id")
        if not pid or pid == self.node_id:
            return
        addrs = info.parsed_addresses()
        if not addrs:
            return
        self.peers[pid] = {
            "id": pid,
            "name": props.get("name", "?"),
            "fp": props.get("fp", ""),
            "host": addrs[0],
            "port": info.port,
            "_sname": name,
        }
        self._notify()

    def _notify(self) -> None:
        peers = [
            {k: v for k, v in p.items() if not k.startswith("_")}
            for p in self.peers.values()
        ]
        self.on_change(peers)

    async def stop(self) -> None:
        try:
            if self._browser:
                await self._browser.async_cancel()
            if self._aiozc and self._info:
                await self._aiozc.async_unregister_service(self._info)
            if self._aiozc:
                await self._aiozc.async_close()
        except Exception:
            pass
