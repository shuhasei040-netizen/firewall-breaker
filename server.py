#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import asyncio
import ssl
import sys

try:
    from websockets.asyncio.server import serve
except ImportError:
    print("エラー: 'websockets' が見つかりません。")
    print("実行: pip install 'websockets>=12.0'")
    sys.exit(1)

CHUNK = 65536

async def handle(conn):
    remote_info = None
    reader = None
    writer = None
    try:
        # 最初のメッセージでターゲットホストとポートを取得
        first = await conn.recv()
        if isinstance(first, (bytes, bytearray)):
            first = bytes(first).decode("utf-8", "replace").strip()
        else:
            first = str(first).strip()
            
        parts = first.split()
        if len(parts) != 2:
            await conn.send(b"ERR bad request format")
            await conn.close()
            return
            
        host, port_str = parts
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError("Port out of range")
        except ValueError:
            await conn.send(b"ERR bad port")
            await conn.close()
            return

        # ターゲットへの接続
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=15.0
            )
        except Exception as e:
            await conn.send(f"ERR upstream: {e}".encode())
            await conn.close()
            return
            
        remote_info = f"{host}:{port}"
        await conn.send(b"OK")
        
    except Exception as e:
        print(f"[WS] 接続確立エラー: {e}", flush=True)
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
                await writer.wait_closed()
            except Exception:
                pass

    print(f"[WS] 接続成功: {conn.remote_address} -> {remote_info}", flush=True)
    t1 = asyncio.create_task(to_client())
    t2 = asyncio.create_task(to_target())
    
    try:
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (t1, t2):
            if not t.done():
                t.cancel()

async def main():
    ap = argparse.ArgumentParser(description="Firewall Breaker WS Server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--cert", default="", help="TLS 証明書 (PEM)")
    ap.add_argument("--key", default="", help="TLS 秘密鍵 (PEM)")
    ap.add_argument("--no-tls", action="store_true", help="TLS なし (Nginx 等用)")
    args = ap.parse_args()

    sslctx = None
    if not args.no_tls:
        if not args.cert or not args.key:
            print("警告: --cert と --key が指定されていないため、自己署名証明書を生成します。")
            import subprocess, os
            if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
                subprocess.run([
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "3650", "-keyout", "key.pem", "-out", "cert.pem",
                    "-subj", "/CN=tunnel.local"
                ], check=True)
            args.cert = "cert.pem"
            args.key = "key.pem"
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sslctx.load_cert_chain(args.cert, args.key)

    print(f"リッスン開始: {args.host}:{args.port} (TLS: {'有効' if sslctx else '無効'})")
    # ping_interval を追加して、ファイアウォールによるサイレント切断を防止
    async with serve(handle, args.host, args.port, ssl=sslctx,
                     max_size=None, ping_interval=25, ping_timeout=60):
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n停止しました。")
