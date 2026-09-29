#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server.py - 自前の VPS に置く WS タンネルの「サーバー側」。

流れ: ローカルアプリ --TLS/WS(443)--> ここ --TCP--> 目的のサイト

起動:
    pip install "websockets>=12"
    # 正規証明書 (Let's Encrypt 等) を持ってる場合:
    python server.py --cert /path/fullchain.pem --key /path/privkey.pem --port 443
    # 自Signed 証明書を作る場合:
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \\
        -keyout key.pem -out cert.pem -subj "/CN=tunnel.example.com"
    sudo python server.py --cert cert.pem --key key.pem --port 443
    # Nginx で TLS を终结させる場合 (README 参照):
    python server.py --no-tls --host 127.0.0.1 --port 8443
"""

import argparse
import asyncio
import ssl

try:
    from websockets.asyncio.server import serve
except ImportError:
    print("'websockets' が入っていません (v12 以降必須)。")
    print("実行: pip install 'websockets>=12'")
    raise SystemExit(1)

CHUNK = 65536


async def handle(conn):
    remote_info = None
    try:
        first = await conn.recv()
        if isinstance(first, (bytes, bytearray)):
            first = bytes(first).decode("utf-8", "replace")
        parts = str(first).split()
        if len(parts) != 2:
            await conn.send(b"ERR bad request")
            await conn.close()
            return
        host, port = parts[0], int(parts[1])
        if not (1 <= port <= 65535):
            await conn.send(b"ERR bad port")
            await conn.close()
            return
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except Exception as e:
            await conn.send(f"ERR upstream: {e}".encode())
            await conn.close()
            return
        remote_info = f"{host}:{port}"
        await conn.send(b"OK")
    except Exception:
        try:
            await conn.close()
        except Exception:
            pass
        return

    async def to_client():
        try:
            while True:
                data = await reader.read(CHUNK)
                if not data:
                    break
                await conn.send(data)
        except Exception:
            pass
        finally:
            try:
                await conn.close()
            except Exception:
                pass

    async def to_target():
        try:
            while True:
                msg = await conn.recv()
                if isinstance(msg, (bytes, bytearray)):
                    writer.write(bytes(msg))
                    await writer.drain()
                else:
                    break
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
            try:
                await writer.wait_closed()
            except Exception:
                pass

    print(f"[WS] {conn.remote_address} -> {remote_info}", flush=True)
    t1 = asyncio.create_task(to_client())
    t2 = asyncio.create_task(to_target())
    try:
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (t1, t2):
            if not t.done():
                t.cancel()


async def main():
    ap = argparse.ArgumentParser(description="壁越え WS タンネル サーバー")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--cert", default="", help="TLS 証明書 (PEM)")
    ap.add_argument("--key", default="", help="TLS 秘密鍵 (PEM)")
    ap.add_argument("--no-tls", action="store_true",
                    help="TLS なしで起動 (Nginx 等が TLS を终结させる場合)")
    args = ap.parse_args()

    sslctx = None
    if not args.no_tls:
        if not args.cert or not args.key:
            ap.error("--cert と --key の両方を指定してください (または --no-tls)")
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sslctx.load_cert_chain(args.cert, args.key)

    print(f"リスニング: {args.host}:{args.port} (TLS: {'有効' if sslctx else '無効'})")
    async with serve(handle, args.host, args.port, ssl=sslctx,
                     max_size=None, ping_interval=30, ping_timeout=90):
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n停止しました。")
