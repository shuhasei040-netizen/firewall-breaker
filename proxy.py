# -*- coding: utf-8 -*-
"""
proxy.py - localhost で SOCKS5 + HTTP プロキシを回す。
ここを通った接続はすべてトンネル(tunnel.py)経由で先頭に転送される。
"""

import socket
import struct
import threading
import urllib.parse

SOCKS_PORT_DEFAULT = 10800
HTTP_PORT_DEFAULT = 10801
CHUNK = 65536
IDLE_TIMEOUT = 600  # 10 分無通信で切断


def pump(a, b):
    """双方向データ中継。片方が終わったら両側を閉じて終了。"""

    def copy(x, y):
        try:
            while True:
                data = x.recv(CHUNK)
                if not data:
                    break
                y.sendall(data)
        except Exception:
            pass
        finally:
            for p in (x, y):
                try:
                    p.close()
                except Exception:
                    pass

    t1 = threading.Thread(target=copy, args=(a, b), daemon=True)
    t2 = threading.Thread(target=copy, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def _split_hostport(s, default_port):
    s = s.strip()
    if s.startswith("["):
        i = s.find("]")
        if i > 0:
            host = s[1:i]
            rest = s[i + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, int(rest[1:])
    h, sep, p = s.rpartition(":")
    if sep and p.isdigit():
        return (h or "::"), int(p)
    return s, default_port


class ProxyServer:
    def __init__(self, tunnel, socks_port=SOCKS_PORT_DEFAULT,
                 http_port=HTTP_PORT_DEFAULT, log=print):
        self.tunnel = tunnel
        self.socks_port = int(socks_port)
        self.http_port = int(http_port)
        self.log = log
        self._running = False
        self._sockets = []
        self._threads = []

    # ------------------------------------------------ 起動 / 停止
    def start(self):
        if self._running:
            return
        self._running = True
        started = []
        try:
            for proto, port in (("SOCKS5", self.socks_port),
                                ("HTTP", self.http_port)):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("127.0.0.1", port))
                    s.listen(128)
                except OSError as e:
                    s.close()
                    raise RuntimeError(
                        f"{proto} プロキシのポート {port} を開けませんでした: {e}\n"
                        f"他のソフトが同じポートを使っていないか、別のポートに変更してください。")
                s.settimeout(1.0)
                started.append(s)
                t = threading.Thread(target=self._accept_loop,
                                     args=(proto, s), daemon=True)
                t.start()
                self._threads.append(t)
                self.log(f"{proto} プロキシ起動: 127.0.0.1:{port}")
        except Exception:
            for s in started:
                try:
                    s.close()
                except Exception:
                    pass
            self._running = False
            raise
        self._sockets = started

    def stop(self):
        self._running = False
        for s in self._sockets:
            try:
                s.close()
            except Exception:
                pass
        self._sockets = []
        for t in self._threads:
            t.join(timeout=2)
        self._threads = []

    def _accept_loop(self, proto, s):
        while self._running:
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(IDLE_TIMEOUT)
            threading.Thread(target=self._handle, args=(proto, conn, addr),
                             daemon=True).start()

    def _handle(self, proto, conn, addr):
        try:
            if proto == "SOCKS5":
                self._handle_socks5(conn)
            else:
                self._handle_http(conn)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass

    # ------------------------------------------------ SOCKS5
    def _handle_socks5(self, conn):
        def read(n):
            buf = b""
            while len(buf) < n:
                d = conn.recv(n - len(buf))
                if not d:
                    raise OSError("クライアント切断")
                buf += d
            return buf

        ver = read(1)[0]
        if ver != 5:
            conn.close()
            return
        read(read(1)[0])          # 認証方式の数
        conn.sendall(b"\x05\x00")  # 認証不要
        ver, cmd, _rsv, atyp = struct.unpack(">BBBH", read(4))
        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, read(4))
        elif atyp == 3:
            host = read(read(1)[0]).decode("utf-8", "replace")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, read(16))
        else:
            conn.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            conn.close()
            return
        dport = struct.unpack(">H", read(2))[0]

        if cmd != 1:  # CONNECT のみサポート
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            conn.close()
            return

        try:
            remote = self.tunnel.open(host, dport)
        except Exception as e:
            self.log(f"SOCKS5 先達不能 {host}:{dport} ({e})")
            conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)  # 接続拒否
            conn.close()
            return

        conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 4 + struct.pack(">H", 0))
        self.log(f"SOCKS5 -> {host}:{dport}")
        pump(conn, remote)

    # ------------------------------------------------ HTTP
    def _handle_http(self, conn):
        def read_until(sep, limit=262144):
            buf = b""
            while sep not in buf:
                d = conn.recv(65536)
                if not d:
                    return None
                buf += d
                if len(buf) > limit:
                    return None
            return buf

        raw = read_until(b"\r\n\r\n")
        if raw is None:
            conn.close()
            return
        head, _, rest = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        req = lines[0].decode("latin-1")
        parts = req.split(" ")
        if len(parts) < 3:
            conn.close()
            return
        method, target = parts[0].upper(), parts[1]

        if method == "CONNECT":
            host, port = _split_hostport(target, 443)
            try:
                remote = self.tunnel.open(host, port)
            except Exception as e:
                self.log(f"CONNECT 先達不能 {host}:{port} ({e})")
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                conn.close()
                return
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            self.log(f"HTTP CONNECT -> {host}:{port}")
            pump(conn, remote)
            return

        # 通常の HTTP リクエスト (GET / POST ...)
        parsed = urllib.parse.urlsplit(target)
        if parsed.hostname:
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            new_target = parsed.path or "/"
            if parsed.query:
                new_target += "?" + parsed.query
        else:
            host, port = None, 80
            new_target = target
            for l in lines[1:]:
                if l.lower().startswith(b"host:"):
                    host, port = _split_hostport(
                        l[5:].decode("latin-1").strip(), 80)
                    break
            if host is None:
                conn.close()
                return

        try:
            remote = self.tunnel.open(host, port)
        except Exception as e:
            self.log(f"HTTP 先達不能 {host}:{port} ({e})")
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            conn.close()
            return

        new_head = (b" ".join((method.encode("latin-1"),
                               new_target.encode("latin-1"),
                               b"HTTP/1.1"))
                    + b"\r\n" + b"\r\n".join(lines[1:]) + b"\r\n\r\n")
        remote.sendall(new_head + rest)
        self.log(f"HTTP {method} -> {host}:{port}")
        pump(conn, remote)
