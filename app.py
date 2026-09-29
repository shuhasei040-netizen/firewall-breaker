#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app.py - 「壁越えトンネル」メイン画面。
ファイアウォール / 規制を回避するための簡易ローカルプロキシツール。

使い方:
    pip install -r requirements.txt
    python app.py
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import queue
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import scrolledtext
import webbrowser

from tunnel import create_tunnel, TunnelError
from proxy import ProxyServer, SOCKS_PORT_DEFAULT, HTTP_PORT_DEFAULT

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(APP_DIR, "settings.json")
TEST_URL = "https://www.google.com/"


class App:
    def __init__(self, root):
        self.root = root
        root.title("壁越えトンネル - ファイアウォール回避プロキシ")
        root.geometry("680x560")
        root.minsize(600, 480)

        self.tunnel = None
        self.proxy = None
        self.busy = False
        self._proxy_applied = False
        self.q = queue.Queue()

        self._build_ui()
        self._load_config()
        self._append_log("起動しました。リモートサーバー(VPS)の情報を入力して [接続] を押してください。")
        root.protocol("WM_DELETE_WINDOW", self.on_exit)
        self._poll_queue()

    # ------------------------------------------------ UI
    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}
        self.root.columnconfigure(0, weight=1)

        rf = ttk.LabelFrame(self.root, text=" リモート (VPS など) ")
        rf.grid(row=0, column=0, sticky="nsew", **pad)
        rf.columnconfigure(1, weight=1)

        ttk.Label(rf, text="モード:").grid(row=0, column=0, sticky="w", padx=6, pady=3)
        self.mode_var = tk.StringVar(value="SSH")
        self.mode_box = ttk.Combobox(rf, textvariable=self.mode_var,
                                     values=["SSH", "HTTPS (WebSocket)"],
                                     state="readonly", width=16)
        self.mode_box.grid(row=0, column=1, columnspan=3, sticky="w", padx=6, pady=3)
        self.mode_box.bind("<<ComboboxSelected>>", lambda _e: self._on_mode())

        self.host_var = tk.StringVar(value="example.com")
        self._row(rf, 1, "ホスト:", self.host_var)
        self.port_var = tk.StringVar(value="22")
        self._row(rf, 2, "ポート:", self.port_var, width=8)
        self.user_var = tk.StringVar()
        self._row(rf, 3, "ユーザー名:", self.user_var)
        self.pwd_var = tk.StringVar()
        self._row(rf, 4, "パスワード:", self.pwd_var, show="*")

        kf = ttk.Frame(rf)
        kf.grid(row=5, column=0, columnspan=4, sticky="we", padx=6, pady=3)
        ttk.Label(kf, text="鍵ファイル (SSH パスワードとどちらか):").pack(side="left")
        self.key_var = tk.StringVar()
        ttk.Entry(kf, textvariable=self.key_var, width=30).pack(side="left", padx=4)
        ttk.Button(kf, text="参照…", command=self._browse_key).pack(side="left")

        self.verify_var = tk.IntVar(value=0)
        ttk.Checkbutton(rf, text="TLS 証明書を検証 (本物の証明書があるときのみ。自Signed はチェックを外す)",
                        variable=self.verify_var).grid(row=6, column=1, columnspan=3, sticky="w")

        lf = ttk.LabelFrame(self.root, text=" ローカルプロキシ (ブラウザ/アプリがこれに接続) ")
        lf.grid(row=1, column=0, sticky="ew", **pad)
        self.socks_var = tk.StringVar(value=str(SOCKS_PORT_DEFAULT))
        self.http_var = tk.StringVar(value=str(HTTP_PORT_DEFAULT))
        ttk.Label(lf, text="SOCKS5 ポート:").pack(side="left", padx=(8, 4))
        ttk.Entry(lf, textvariable=self.socks_var, width=8).pack(side="left")
        ttk.Label(lf, text="   HTTP ポート:").pack(side="left", padx=(8, 4))
        ttk.Entry(lf, textvariable=self.http_var, width=8).pack(side="left")
        self.proxy_check_var = tk.IntVar(value=0)
        ttk.Checkbutton(lf, text="システムプロキシに適用 (Windows のみ)",
                        variable=self.proxy_check_var).pack(side="left", padx=12)

        bf = ttk.Frame(self.root)
        bf.grid(row=2, column=0, sticky="ew", **pad)
        self.btn_connect = ttk.Button(bf, text="接続", command=self.on_connect)
        self.btn_connect.pack(side="left", padx=(0, 6))
        self.btn_disconnect = ttk.Button(bf, text="切断",
                                         command=self.on_disconnect, state="disabled")
        self.btn_disconnect.pack(side="left", padx=(0, 6))
        ttk.Button(bf, text="ブラウザで開く",
                   command=lambda: self.on_open_browser()).pack(side="left", padx=(0, 6))
        ttk.Button(bf, text="IP 確認", command=self.on_check_ip).pack(side="left", padx=(0, 6))
        ttk.Button(bf, text="設定を保存", command=self._save_config).pack(side="left")

        self.status_var = tk.StringVar(value="状態: 未接続")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w"
                  ).grid(row=3, column=0, sticky="ew", padx=8)

        self.log_text = scrolledtext.ScrolledText(
            self.root, height=10, state="disabled", font=("Consolas", 9))
        self.log_text.grid(row=4, column=0, sticky="nsew", **pad)
        self.root.rowconfigure(4, weight=1)

    def _row(self, parent, row, label, var, width=None, show=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=6, pady=2)
        kw = {}
        if width:
            kw["width"] = width
        if show:
            kw["show"] = show
        ttk.Entry(parent, textvariable=var, **kw).grid(
            row=row, column=1, sticky="we", padx=6, pady=2)

    def _on_mode(self):
        if self.mode_var.get().startswith("SSH"):
            if self.port_var.get() == "443":
                self.port_var.set("22")
        else:
            if self.port_var.get() == "22":
                self.port_var.set("443")

    def _browse_key(self):
        p = filedialog.askopenfilename(
            title="SSH 秘密鍵を選択",
            filetypes=[("鍵ファイル", "*.pem *.ppk *.key"), ("全ファイル", "*.*")])
        if p:
            self.key_var.set(p)

    # ------------------------------------------------ ログ / キュー
    def log(self, msg):
        self.q.put(("log", msg))

    def _append_log(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{ts}] {msg}\n")
        lines = int(self.log_text.index("end-1c").split(".")[0])
        if lines > 500:
            self.log_text.delete("1.0", f"{lines - 500}.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "connected":
                    self._update_connected(True, payload)
                elif kind == "disconnected":
                    self._update_connected(False, None)
                elif kind == "error":
                    self.busy = False
                    self._set_buttons(connect_enabled=True)
                    self._append_log("エラー: " + payload)
                    messagebox.showerror("エラー", payload)
        except queue.Empty:
            pass
        self.root.after(80, self._poll_queue)

    def _update_connected(self, on, info):
        if on:
            host, port = info
            self.status_var.set(
                f"状態: 接続中 ({self.mode_var.get()} -> {host}:{port})")
            self._set_buttons(connect_enabled=False)
            if self.proxy_check_var.get():
                if self._set_system_proxy_on():
                    self.log("システム設定にローカルプロキシを適用しました。")
                else:
                    self.log("システム適用には Windows が条件です。ブラウザのプロキシを手動設定してください。")
            self.log(f"接続完了。ブラウザ/アプリは SOCKS 127.0.0.1:{self.proxy.socks_port}"
                     f" または HTTP 127.0.0.1:{self.proxy.http_port} に接続。")
        else:
            self.busy = False
            self.status_var.set("状態: 未接続")
            self._set_buttons(connect_enabled=True)

    def _set_buttons(self, connect_enabled):
        self.btn_connect.configure(state="normal" if connect_enabled else "disabled")
        st = "normal" if self.tunnel else "disabled"
        self.btn_disconnect.configure(state=st)

    # ------------------------------------------------ 接続 / 切断
    def on_connect(self):
        if self.busy or self.tunnel:
            return
        self.busy = True
        self._set_buttons(connect_enabled=False)
        self._append_log("接続中…")
        threading.Thread(target=self._connect_worker, daemon=True).start()

    def _connect_worker(self):
        tunnel, proxy = None, None
        try:
            mode = "ssh" if self.mode_var.get().startswith("SSH") else "ws"
            host = self.host_var.get().strip()
            port = int(self.port_var.get())
            socks = int(self.socks_var.get())
            http = int(self.http_var.get())
            if not host:
                raise ValueError("ホストを入力してください。")
            tunnel = create_tunnel(mode, host, port,
                                   username=self.user_var.get().strip(),
                                   password=self.pwd_var.get(),
                                   key_file=self.key_var.get().strip(),
                                   ssl_verify=bool(self.verify_var.get()))
            tunnel.connect()
            proxy = ProxyServer(tunnel, socks_port=socks, http_port=http,
                                log=self.log)
            proxy.start()
            self.tunnel, self.proxy = tunnel, proxy
            tunnel, proxy = None, None
            self.q.put(("connected", (host, port)))
        except (ValueError, TunnelError, RuntimeError) as e:
            self.q.put(("error", str(e)))
        except Exception as e:
            self.q.put(("error", f"不明なエラー: {e}"))
        finally:
            if proxy:
                try:
                    proxy.stop()
                except Exception:
                    pass
            if tunnel:
                try:
                    tunnel.close()
                except Exception:
                    pass

    def on_disconnect(self):
        if not self.tunnel:
            return
        threading.Thread(target=self._do_disconnect, daemon=True).start()

    def _do_disconnect(self):
        p, t = self.proxy, self.tunnel
        self.tunnel, self.proxy = None, None
        try:
            if p:
                p.stop()
        except Exception:
            pass
        try:
            if t:
                t.close()
        except Exception:
            pass
        self._set_system_proxy_off()
        self.q.put(("disconnected", None))
        self.log("切断しました。")

    # ------------------------------------------------ ブラウザ / IP 確認
    def on_open_browser(self, url=TEST_URL):
        if not self.proxy:
            messagebox.showinfo("お知らせ", "先に接続してください。")
            return
        browser = self._find_browser()
        if browser:
            profile = os.path.join(tempfile.gettempdir(), "wallbreaker_profile")
            cmd = [browser,
                   f"--proxy-server=127.0.0.1:{self.proxy.http_port}",
                   f"--user-data-dir={profile}",
                   url]
            try:
                subprocess.Popen(cmd, close_fds=True,
                                 creationflags=getattr(
                                     subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
                self.log(f"プロキシ付きでブラウザを開きました ({browser})")
                return
            except OSError as e:
                self.log(f"ブラウザ起動失敗: {e}")
        if not self._set_system_proxy_on():
            self.log(f"ブラウザが見つからないため手動設定が必要です。"
                     f"プロキシ: 127.0.0.1:{self.proxy.http_port} (HTTP) / "
                     f"127.0.0.1:{self.proxy.socks_port} (SOCKS5)")
        webbrowser.open_new_tab(url)

    @staticmethod
    def _find_browser():
        if sys.platform == "win32":
            cands = [
                os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
                os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
            ]
            for p in cands:
                if os.path.exists(p):
                    return p
        elif sys.platform == "darwin":
            for p in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"):
                if os.path.exists(p):
                    return p
        else:
            for p in ("google-chrome", "google-chrome-stable", "chromium",
                      "chromium-browser", "microsoft-edge", "msedge"):
                if shutil.which(p):
                    return p
        return None

    def on_check_ip(self):
        if not self.tunnel:
            messagebox.showinfo("お知らせ", "先に接続してください。")
            return
        threading.Thread(target=self._check_ip_worker, daemon=True).start()

    def _check_ip_worker(self):
        self.log("中継 IP を確認中…")
        targets = [
            ("api.ipify.org", 80, "GET /"),
            ("icanhazip.com", 80, "GET /"),
            ("ifconfig.me", 80, "GET /ip"),
            ("ipinfo.io", 80, "GET /ip"),
        ]
        for host, port, path in targets:
            try:
                c = self.tunnel.open(host, port)
                req = (f"{path} HTTP/1.1\r\nHost: {host}\r\n"
                       "User-Agent: wallbreaker/1.0\r\nConnection: close\r\n\r\n")
                c.sendall(req.encode())
                buf = b""
                for _ in range(100):
                    d = c.recv(4096)
                    if not d:
                        break
                    buf += d
                try:
                    c.close()
                except Exception:
                    pass
                body = buf.split(b"\r\n\r\n", 1)[-1].decode("utf-8", "replace")
                m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", body)
                if m:
                    self.log(f"中継 IP (外から見られる IP): {m.group(0)}")
                    return
            except Exception:
                continue
        self.log("中継 IP を確認できませんでした (確認先自体がブロックされている可能性があります)。")

    # ------------------------------------------------ システムプロキシ (Windows)
    @staticmethod
    def _ie_refresh():
        if sys.platform != "win32":
            return
        try:
            import ctypes
            windll = ctypes.windll.wininet
            windll.InternetSetOptionW(0, 25, None, 0)  # SETTINGS_CHANGED
            windll.InternetSetOptionW(0, 26, None, 0)  # REFRESH
        except Exception:
            pass

    def _set_system_proxy_on(self):
        if sys.platform != "win32" or not self.proxy:
            return False
        try:
            import winreg
            path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE)
            try:
                winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ,
                                  "127.0.0.1:%d" % self.proxy.http_port)
            finally:
                winreg.CloseKey(k)
            self._ie_refresh()
            self._proxy_applied = True
            return True
        except OSError:
            return False

    def _set_system_proxy_off(self):
        if not self._proxy_applied:
            return
        try:
            import winreg
            path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE)
            try:
                winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            finally:
                winreg.CloseKey(k)
        except OSError:
            pass
        self._ie_refresh()
        self._proxy_applied = False

    # ------------------------------------------------ 設定の保存 / 読み込み
    def _save_config(self):
        try:
            data = {
                "mode": self.mode_var.get(),
                "host": self.host_var.get(),
                "port": self.port_var.get(),
                "user": self.user_var.get(),
                "password": self.pwd_var.get(),
                "key": self.key_var.get(),
                "verify": int(self.verify_var.get()),
                "socks": self.socks_var.get(),
                "http": self.http_var.get(),
                "setproxy": int(self.proxy_check_var.get()),
            }
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.log(f"設定を {CONFIG_PATH} に保存しました (パスワードは平文です)。")
        except OSError as e:
            messagebox.showerror("エラー", f"設定を保存できませんでした: {e}")

    def _load_config(self):
        if not os.path.exists(CONFIG_PATH):
            return
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            return
        self.mode_var.set(d.get("mode", "SSH"))
        if "host" in d:
            self.host_var.set(d["host"])
        if "port" in d:
            self.port_var.set(str(d["port"]))
        if "user" in d:
            self.user_var.set(d["user"])
        if "password" in d:
            self.pwd_var.set(d["password"])
        if "key" in d:
            self.key_var.set(d["key"])
        self.verify_var.set(int(d.get("verify", 0)))
        if "socks" in d:
            self.socks_var.set(str(d["socks"]))
        if "http" in d:
            self.http_var.set(str(d["http"]))
        self.proxy_check_var.set(int(d.get("setproxy", 0)))

    # ------------------------------------------------ 終了
    def on_exit(self):
        try:
            if self.tunnel:
                self._do_disconnect()
        except Exception:
            pass
        self._save_config()
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except tk.TclError:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
