"""
Single-file VLESS + Trojan over WebSocket proxy for Railway.
Serves a decoy game page at '/', a base64 subscription at SUB_PATH,
and tunnels proxy traffic over a WebSocket path.

Env vars (set these in the Railway dashboard):
    UUID         - VLESS user UUID (e.g. generate with `python3 -c "import uuid;print(uuid.uuid4())"`)
    TROJAN_PASS  - Trojan password (any string)
    WS_PATH      - WebSocket path clients connect to, e.g. /ws-a1b2
    SUB_PATH     - Path that returns the base64 subscription, e.g. /sub-x9z
    DOMAIN       - Public domain Railway gives you (or your custom domain), no scheme
    PORT         - Provided automatically by Railway
"""

import asyncio
import base64
import hashlib
import os
import struct
import uuid as uuid_mod

from aiohttp import web, WSMsgType

UUID = os.environ.get("UUID", "a3f1c2d4-5b6a-4e7f-9c8d-1a2b3c4d5e6f")
TROJAN_PASS = os.environ.get("TROJAN_PASS", "change-me-password")
WS_PATH = os.environ.get("WS_PATH", "/ws")
SUB_PATH = os.environ.get("SUB_PATH", "/sub")
DOMAIN = os.environ.get("DOMAIN", "example.up.railway.app")
PORT = int(os.environ.get("PORT", "8080"))

TROJAN_HASH = hashlib.sha224(TROJAN_PASS.encode()).hexdigest().encode()
UUID_BYTES = uuid_mod.UUID(UUID).bytes

CHUNK = 32 * 1024


# ---------- outbound relay helpers ----------

async def pipe(reader: asyncio.StreamReader, ws: web.WebSocketResponse, closer):
    try:
        while True:
            data = await reader.read(CHUNK)
            if not data:
                break
            await ws.send_bytes(data)
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    finally:
        closer()


async def read_addr(buf: bytes, i: int):
    atyp = buf[i]
    i += 1
    if atyp == 1:  # IPv4
        addr = ".".join(str(b) for b in buf[i:i + 4])
        i += 4
    elif atyp == 2:  # domain
        ln = buf[i]
        i += 1
        addr = buf[i:i + ln].decode()
        i += ln
    elif atyp == 3:  # IPv6
        addr = ":".join(buf[i:i + 16].hex()[j:j + 4] for j in range(0, 32, 4))
        i += 16
    else:
        raise ValueError("bad atyp")
    return addr, i


# ---------- VLESS ----------

async def handle_vless(ws: web.WebSocketResponse, first: bytes):
    # layout: ver(1) uuid(16) addon_len(1) addons(n) cmd(1) port(2) atyp... addr... payload...
    if len(first) < 24 or first[1:17] != UUID_BYTES:
        await ws.close()
        return

    i = 17
    addon_len = first[i]
    i += 1 + addon_len
    cmd = first[i]
    i += 1
    if cmd != 1:  # only TCP supported
        await ws.close()
        return
    port = struct.unpack(">H", first[i:i + 2])[0]
    i += 2
    addr, i = await read_addr(first, i)
    payload = first[i:]

    try:
        reader, writer = await asyncio.open_connection(addr, port)
    except OSError:
        await ws.close()
        return

    # VLESS response header: version(1) + addon_len(1, =0)
    await ws.send_bytes(bytes([0, 0]))

    if payload:
        writer.write(payload)
        await writer.drain()

    def closer():
        if not writer.is_closing():
            writer.close()

    relay_task = asyncio.create_task(pipe(reader, ws, closer))
    try:
        async for msg in ws:
            if msg.type == WSMsgType.BINARY:
                writer.write(msg.data)
                await writer.drain()
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                break
    finally:
        closer()
        relay_task.cancel()


# ---------- Trojan ----------

async def handle_trojan(ws: web.WebSocketResponse, first: bytes):
    # layout: hex(sha224(pass))(56) CRLF cmd(1) atyp(1) addr port(2) CRLF payload
    if len(first) < 58 or first[:56] != TROJAN_HASH:
        await ws.close()
        return

    i = 58  # skip hash + CRLF
    cmd = first[i]
    i += 1
    if cmd != 1:
        await ws.close()
        return
    addr, i = await read_addr(first, i)
    port = struct.unpack(">H", first[i:i + 2])[0]
    i += 2
    i += 2  # trailing CRLF
    payload = first[i:]

    try:
        reader, writer = await asyncio.open_connection(addr, port)
    except OSError:
        await ws.close()
        return

    if payload:
        writer.write(payload)
        await writer.drain()

    def closer():
        if not writer.is_closing():
            writer.close()

    relay_task = asyncio.create_task(pipe(reader, ws, closer))
    try:
        async for msg in ws:
            if msg.type == WSMsgType.BINARY:
                writer.write(msg.data)
                await writer.drain()
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                break
    finally:
        closer()
        relay_task.cancel()


# ---------- HTTP / WS routes ----------

async def ws_handler(request: web.Request):
    ws = web.WebSocketResponse(protocols=("vless", "trojan"))
    await ws.prepare(request)

    first_msg = await ws.receive()
    if first_msg.type != WSMsgType.BINARY:
        await ws.close()
        return ws

    first = first_msg.data

    if len(first) >= 56 and first[:56] == TROJAN_HASH:
        await handle_trojan(ws, first)
    else:
        await handle_vless(ws, first)

    return ws


async def index_handler(request: web.Request):
    here = os.path.dirname(os.path.abspath(__file__))
    return web.FileResponse(os.path.join(here, "index.html"))


async def health_handler(request: web.Request):
    return web.Response(text="ok")


async def sub_handler(request: web.Request):
    vless_link = (
        f"vless://{UUID}@{DOMAIN}:443?encryption=none&security=tls"
        f"&type=ws&host={DOMAIN}&path={WS_PATH}&sni={DOMAIN}#railway-vless"
    )
    trojan_link = (
        f"trojan://{TROJAN_PASS}@{DOMAIN}:443?security=tls"
        f"&type=ws&host={DOMAIN}&path={WS_PATH}&sni={DOMAIN}#railway-trojan"
    )
    blob = "\n".join([vless_link, trojan_link]).encode()
    return web.Response(text=base64.b64encode(blob).decode())


def build_app():
    app = web.Application()
    app.router.add_get("/", index_handler)
    app.router.add_get("/health", health_handler)
    app.router.add_get(SUB_PATH, sub_handler)
    app.router.add_get(WS_PATH, ws_handler)
    return app


if __name__ == "__main__":
    web.run_app(build_app(), host="0.0.0.0", port=PORT)
