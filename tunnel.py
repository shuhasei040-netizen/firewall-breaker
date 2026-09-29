# -*- coding: utf-8 -*-
"""
tunnel.py - 壁の向こうへ通す「管」。

2 系統:
  SSHTunnel : SSH 動的ポートフォワード (paramiko)。
              どの VPS からも SSH できれば動く。22 が塞がれていても
              VPS 側で 443 に変えれば(README 参照)通信は 443 番経由。
  WSTunnel  : TLS 上の WebSocket タンネル (server.py を VPS に置く必要あり)。
              外部からは通常の HTTPS 通信と区別不能。

共通インターフェース:
    t = create_tunnel(mode, host, port, ...)
    t.connect()
    chan = t.open("example.com", 443)   # socket 風オブジェクト
    chan.sendall(b"..."); chan.recv(65536); chan.close()
    t.close()
"""

import io
import ssl
import asyncio
import threading

__all__ = ["TunnelError", "create_tunnel", "SSHTunnel", "WSTunnel"]


class TunnelError(Exception):
    """ユーザー向け(表示してよい)のトンネルエラー。"""
    pass


def create_tunnel(mode, host, port, username="", password="", key_file="",
                  ssl_verify=False):
    """mode は 'ssh' か 'ws'。"""
    if mode == "ssh":
        return SSHTunnel(host, int(port), username, password, key_file)
    if mode == "ws":
        return WSTunnel(host, int(port), ssl_verify=ssl_verify)
    raise TunnelError(f"不明なモード: {mode}")


# ------------------------------------------------------------ SSH 系
class SSHTunnel:
    """SSH 動的ポートフォワード。全外出通信がリモート側から張られる。"""

    def __init__(self, host, port, username, password, key_file=""):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.key_file = key_file
        self._client = None
        self._transport = None
        self._lock = threading.Lock()

    def _load_key(self):
        import paramiko
        with open(self.key_file, "rb") as f:
            data = f.read()
        last = None
        for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try:
                return cls.from_private_key(io.BytesIO(data))
            except Exception as e:
                last = e
        raise TunnelError(f"鍵ファイルを読み込めません: {last}")

    def connect(self):
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kw = dict(hostname=self.host, port=self.port, username=self.username,
                  timeout=20, banner_timeout=30, auth_timeout=30,
                  allow_agent=False)
        if self.key_file:
            kw["pkey"] = self._load_key()
        else:
            kw["password"] = self.password
            kw["look_for_keys"] = False
        try:
            client.connect(**kw)
        except TunnelError:
            raise
        except Exception as e:
            raise TunnelError(f"SSH 接続に失敗しました ({self.host}:{self.port}): {e}")
        self._client = client
        self._transport = client.get_transport()
        try:
            self._transport.set_keepalive(30)  # 放置切断対策
        except Exception:
            pass

    def open(self, dst, dport):
        """リモート経由で dst:dport への TCP 接続を開く。socket 風オブジェクトを返す。"""
        if self._transport is None or not self._transport.is_active():
            raise TunnelError("未接続です")
        with self._lock:
            try:
                chan = self._transport.open_channel(
                    "forwarded", (dst, int(dport)), timeout=30)
            except Exception as e:
                raise TunnelError(f"{dst}:{dport} への経路を開けませんでした: {e}")
        return chan

    def close(self):
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
            self._transport = None


# -------------------------------------------- WebSocket(TLS) 系
class _WSHandle:
    """WebSocket 接続を socket 風に見せるラッパー (proxy.py の pump() で使う)。"""

    def __init__(self, ws, loop):
        self._ws = ws
        self._loop = loop
        self._closed = False

    def _call(self, coro):
        if self._closed:
            raise OSError("接続は既に閉じられています")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result()

    def recv(self, n=65536):
        data = self._call(self._ws.recv())
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        return bytes(data)

    def sendall(self, data):
        self._call(self._ws.send(bytes(data)))

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            fut = asyncio.run_coroutine_threadsafe(self._ws.close(), self._loop)
            fut.result(timeout=5)
        except Exception:
            pass


class WSTunnel:
    """WebSocket タンネル。通信は TLS 暗号 + 443 番で、外部から見たら
    普通の「サイトへの HTTPS 通信」として見える。リモートに server.py 必須。"""

    def __init__(self, host, port, ssl_verify=False):
        self.host = host
        self.port = int(port) if port else 443
        self.ssl_verify = ssl_verify
        self._loop = None
        self._thread = None
        self._ready = threading.Event()

    def _ssl_ctx(self):
        if self.ssl_verify:
            return ssl.create_default_context()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def connect(self):
        try:
            import websockets  # noqa: F401
        except ImportError:
            raise TunnelError("'websockets' が未導入です。pip install 'websockets>=12'")
        if self._loop is None:
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
            if not self._ready.wait(5):
                raise TunnelError("ローカルの非同期ループが起動しませんでした")

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        self._loop.run_forever()

    def open(self, dst, dport):
        if self._loop is None:
            raise TunnelError("未接続です")
        fut = asyncio.run_coroutine_threadsafe(
            self._open(dst, int(dport)), self._loop)
        try:
            return fut.result(timeout=45)
        except TunnelError:
            raise
        except Exception as e:
            raise TunnelError(f"{dst}:{dport} へのトンネルを開けませんでした: {e}")

    async def _open(self, dst, dport):
        from websockets.asyncio.client import connect
        uri = f"wss://{self.host}:{self.port}/"
        try:
            ws = await connect(uri, ssl=self._ssl_ctx(),
                               open_timeout=30, close_timeout=5,
                               max_size=None,
                               user_agent_header="Mozilla/5.0 (compatible; WBrowser)")
        except Exception as e:
            raise TunnelError(f"サーバー {self.host}:{self.port} に接続できません: {e}")
        try:
            await ws.send(f"{dst} {dport}".encode("ascii"))
            resp = await asyncio.wait_for(ws.recv(), 30)
            if isinstance(resp, (bytes, bytearray)):
                resp = bytes(resp).decode("utf-8", "replace")
            if not str(resp).startswith("OK"):
                raise TunnelError(f"サーバーが拒否しました: {resp}")
        except TunnelError:
            try:
                await ws.close()
            except Exception:
                pass
            raise
        except Exception as e:
            try:
                await ws.close()
            except Exception:
                pass
            raise TunnelError(f"トンネル確立に失敗しました: {e}")
        return _WSHandle(ws, self._loop)

    def close(self):
        if self._loop is not None:
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                pass
            self._loop = None
            self._thread = None
