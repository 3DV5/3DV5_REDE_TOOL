"""
╔══════════════════════════════════════════════════════╗
║         NETWORK DASHBOARD - customtkinter            ║
║  Dependências: pip install customtkinter psutil      ║
║                pip install dnspython requests        ║
╚══════════════════════════════════════════════════════╝
"""

import customtkinter as ctk
import threading
import subprocess
import socket
import ipaddress
import struct
import os
import sys
import time
import json
import re
import speedtest
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

try:
    import dns.resolver
    import dns.reversename
    DNS_OK = True
except ImportError:
    DNS_OK = False

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# when we explicitly disable SSL verification (verify=False) we get an
# `InsecureRequestWarning` from urllib3.  it doesn't break anything but it
# spams stderr; disable it globally so users aren't alarmed when they try an
# HTTP/HTTPS lookup against a site with a bad certificate.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

# ========== NOVAS DEPENDÊNCIAS OPCIONAIS ==========
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    from pysnmp.hlapi import *
    PYSNMP_OK = True
except ImportError:
    PYSNMP_OK = False

try:
    import paramiko
    PARAMIKO_OK = True
except ImportError:
    PARAMIKO_OK = False

try:
    import matplotlib
    matplotlib.use("TkAgg")  # necessário para integrar com tkinter
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    MATPLOTLIB_OK = True
except ImportError:
    MATPLOTLIB_OK = False

try:
    from mac_vendor_lookup import MacLookup
    MAC_VENDOR_OK = True
except ImportError:
    MAC_VENDOR_OK = False    

# ───────────────────────────── TEMA ──────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLORS = {
    "bg":        "#0d1117",
    "sidebar":   "#161b22",
    "card":      "#21262d",
    "border":    "#30363d",
    "accent":    "#58a6ff",
    "accent2":   "#3fb950",
    "accent3":   "#f78166",
    "accent4":   "#d2a8ff",
    "text":      "#c9d1d9",
    "text_dim":  "#8b949e",
    "success":   "#3fb950",
    "warning":   "#d29922",
    "error":     "#f85149",
}

FONT_MONO  = ("Courier New", 11)
FONT_SMALL = ("Segoe UI", 10)
FONT_MED   = ("Segoe UI", 12)
FONT_BOLD  = ("Segoe UI", 13, "bold")
FONT_TITLE = ("Segoe UI", 15, "bold")


# ─────────────────────────── HELPERS ─────────────────────────────
def run_command(cmd: list) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Comando excedeu 30 segundos."
    except FileNotFoundError:
        return f"[ERRO] Comando '{cmd[0]}' não encontrado."
    except Exception as e:
        return f"[ERRO] {e}"


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ──────────────────────── OUTPUT BOX ──────────────────────────────
class OutputBox(ctk.CTkTextbox):
    def __init__(self, master, **kwargs):
        kwargs.setdefault("font", FONT_MONO)
        kwargs.setdefault("fg_color", COLORS["bg"])
        kwargs.setdefault("text_color", COLORS["text"])
        kwargs.setdefault("corner_radius", 8)
        kwargs.setdefault("wrap", "none")
        super().__init__(master, **kwargs)
        self._build_tags()

    def _build_tags(self):
        self.tag_config("success", foreground=COLORS["success"])
        self.tag_config("error",   foreground=COLORS["error"])
        self.tag_config("warning", foreground=COLORS["warning"])
        self.tag_config("accent",  foreground=COLORS["accent"])
        self.tag_config("dim",     foreground=COLORS["text_dim"])
        self.tag_config("bold",    foreground=COLORS["text"])
        self.tag_config("header",  foreground=COLORS["accent4"])

    def clear(self):
        self.configure(state="normal")
        self.delete("1.0", "end")

    def append(self, text: str, tag: str = ""):
        self.configure(state="normal")
        if tag:
            self.insert("end", text, tag)
        else:
            self.insert("end", text)
        self.see("end")
        self.configure(state="disabled")

    def println(self, text: str = "", tag: str = ""):
        self.append(text + "\n", tag)

    def header(self, title: str):
        bar = "─" * 50
        self.println(f"\n{bar}", "dim")
        self.println(f"  {title}  [{ts()}]", "header")
        self.println(bar, "dim")


# ──────────────────────── CARD WIDGET ─────────────────────────────
class Card(ctk.CTkFrame):
    def __init__(self, master, title="", **kwargs):
        kwargs.setdefault("fg_color", COLORS["card"])
        kwargs.setdefault("corner_radius", 10)
        kwargs.setdefault("border_width", 1)
        kwargs.setdefault("border_color", COLORS["border"])
        super().__init__(master, **kwargs)
        if title:
            ctk.CTkLabel(self, text=title, font=FONT_BOLD,
                         text_color=COLORS["accent"]).pack(
                anchor="w", padx=14, pady=(10, 4))


# ═══════════════════════════════════════════════════════════════════
#                         ABAS / FERRAMENTAS
# ═══════════════════════════════════════════════════════════════════

class PingTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Host / IP:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.host = ctk.CTkEntry(top, width=220, placeholder_text="8.8.8.8",
                                  font=FONT_MED)
        self.host.pack(side="left", padx=8)
        self.host.insert(0, "8.8.8.8")

        ctk.CTkLabel(top, text="Pacotes:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.count = ctk.CTkEntry(top, width=60, font=FONT_MED)
        self.count.pack(side="left", padx=8)
        self.count.insert(0, "4")

        self.cont_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(top, text="Contínuo", variable=self.cont_var,
                        font=FONT_SMALL).pack(side="left", padx=8)

        self.btn = ctk.CTkButton(top, text="▶  Ping", width=110,
                                  fg_color=COLORS["accent"],
                                  command=self._run)
        self.btn.pack(side="left", padx=4)

        ctk.CTkButton(top, text="✖ Parar", width=90,
                       fg_color=COLORS["accent3"],
                       command=self._stop).pack(side="left", padx=4)

        self._stop_flag = False

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)
        self.out.configure(state="disabled")

    def _run(self):
        self._stop_flag = False
        threading.Thread(target=self._ping_thread, daemon=True).start()

    def _stop(self):
        self._stop_flag = True

    def _ping_thread(self):
        host = self.host.get().strip() or "8.8.8.8"
        count = self.count.get().strip()
        continuous = self.cont_var.get()

        self.out.clear()
        self.out.header(f"PING → {host}")

        times = []
        n = 0
        while not self._stop_flag:
            n += 1
            t0 = time.time()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                ip = socket.gethostbyname(host)
                sock.connect((ip, 80))
                sock.close()
                ms = (time.time() - t0) * 1000
                times.append(ms)
                tag = "success" if ms < 100 else "warning"
                self.out.println(
                    f"  [{ts()}] seq={n:>3}  {ip}  {ms:>7.2f} ms  ✓", tag)
            except Exception as e:
                self.out.println(
                    f"  [{ts()}] seq={n:>3}  FALHA → {e}", "error")

            if not continuous and n >= int(count or 4):
                break
            if not self._stop_flag:
                time.sleep(1)

        if times:
            self.out.println()
            self.out.println(f"  Enviados: {n}  Recebidos: {len(times)}  "
                             f"Perdidos: {n - len(times)}", "dim")
            self.out.println(f"  Min: {min(times):.2f}ms  "
                             f"Max: {max(times):.2f}ms  "
                             f"Avg: {sum(times)/len(times):.2f}ms", "accent")


# ─────────────────────────────────────────────────────────────────
class TracerouteTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Destino:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.host = ctk.CTkEntry(top, width=250,
                                  placeholder_text="google.com",
                                  font=FONT_MED)
        self.host.pack(side="left", padx=8)
        self.host.insert(0, "google.com")

        ctk.CTkLabel(top, text="Max hops:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.hops = ctk.CTkEntry(top, width=60, font=FONT_MED)
        self.hops.pack(side="left", padx=8)
        self.hops.insert(0, "20")

        ctk.CTkButton(top, text="▶  Traceroute", width=130,
                       fg_color=COLORS["accent2"],
                       command=self._run).pack(side="left", padx=4)

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)
        self.out.configure(state="disabled")

    def _run(self):
        threading.Thread(target=self._trace_thread, daemon=True).start()

    def _trace_thread(self):
        host = self.host.get().strip() or "google.com"
        max_hops = int(self.hops.get().strip() or 20)

        self.out.clear()
        self.out.header(f"TRACEROUTE → {host}")

        is_win = sys.platform == "win32"
        cmd = (["tracert", "-d", "-h", str(max_hops), host]
               if is_win else
               ["traceroute", "-n", "-m", str(max_hops), host])

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                tag = ""
                if "*" in line:
                    tag = "warning"
                elif any(c.isdigit() for c in line):
                    tag = "text"
                self.out.println(line.rstrip(), tag)
        except FileNotFoundError:
            self.out.println(
                f"[ERRO] traceroute não encontrado. "
                f"Instale: sudo apt install traceroute", "error")


# ─────────────────────────────────────────────────────────────────
class PortScannerTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._stop_flag = False
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Host:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.host = ctk.CTkEntry(top, width=200, placeholder_text="192.168.1.1",
                                  font=FONT_MED)
        self.host.pack(side="left", padx=6)

        ctk.CTkLabel(top, text="Portas:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.ports = ctk.CTkEntry(top, width=140,
                                   placeholder_text="1-1024 ou 22,80,443",
                                   font=FONT_MED)
        self.ports.pack(side="left", padx=6)
        self.ports.insert(0, "1-1024")

        ctk.CTkLabel(top, text="Threads:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.threads = ctk.CTkEntry(top, width=60, font=FONT_MED)
        self.threads.pack(side="left", padx=6)
        self.threads.insert(0, "100")

        ctk.CTkLabel(top, text="Timeout(s):", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.timeout = ctk.CTkEntry(top, width=60, font=FONT_MED)
        self.timeout.pack(side="left", padx=6)
        self.timeout.insert(0, "0.5")

        ctk.CTkButton(top, text="▶  Scan", width=100,
                       fg_color=COLORS["accent"],
                       command=self._run).pack(side="left", padx=4)
        ctk.CTkButton(top, text="✖ Parar", width=90,
                       fg_color=COLORS["accent3"],
                       command=self._stop).pack(side="left", padx=4)

        # Preset buttons
        presets = ctk.CTkFrame(self, fg_color="transparent")
        presets.pack(fill="x", padx=10, pady=(0, 4))
        for label, val in [("Web", "80,443,8080,8443"),
                           ("SSH/FTP", "21,22,23"),
                           ("DB",    "3306,5432,27017,6379"),
                           ("Mail",  "25,110,143,587,993"),
                           ("Top100","1-100")]:
            ctk.CTkButton(presets, text=label, width=80, height=26,
                           font=FONT_SMALL,
                           fg_color=COLORS["sidebar"],
                           border_width=1, border_color=COLORS["border"],
                           command=lambda v=val: self._set_ports(v)
                           ).pack(side="left", padx=3)

        self.progress = ctk.CTkProgressBar(self, mode="determinate")
        self.progress.set(0)
        self.progress.pack(fill="x", padx=10, pady=2)

        self.out = OutputBox(self, height=380)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)
        self.out.configure(state="disabled")

    def _set_ports(self, v):
        self.ports.delete(0, "end")
        self.ports.insert(0, v)

    def _stop(self):
        self._stop_flag = True

    def _parse_ports(self, s: str) -> list:
        ports = []
        for part in s.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                ports.extend(range(int(a), int(b) + 1))
            else:
                ports.append(int(part))
        return ports

    def _run(self):
        self._stop_flag = False
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        host = self.host.get().strip()
        if not host:
            self.out.clear()
            self.out.println("[ERRO] Informe um host.", "error")
            return

        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            self.out.clear()
            self.out.println(f"[ERRO] DNS: {e}", "error")
            return

        try:
            port_list = self._parse_ports(self.ports.get())
        except ValueError:
            self.out.clear()
            self.out.println("[ERRO] Formato de portas inválido.", "error")
            return

        max_threads = int(self.threads.get() or 100)
        timeout = float(self.timeout.get() or 0.5)
        open_ports = []
        lock = threading.Lock()
        sem = threading.Semaphore(max_threads)
        done = [0]
        total = len(port_list)

        self.out.clear()
        self.out.header(f"PORT SCAN → {host} ({ip})")
        self.out.println(f"  Portas: {total}  Threads: {max_threads}  "
                         f"Timeout: {timeout}s", "dim")
        self.progress.set(0)

        KNOWN = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP-TLS",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            27017: "MongoDB",
        }

        def check(p):
            if self._stop_flag:
                return
            with sem:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    r = s.connect_ex((ip, p))
                    s.close()
                    if r == 0:
                        svc = KNOWN.get(p, "?")
                        with lock:
                            open_ports.append(p)
                            self.out.println(
                                f"  [{ts()}] ✓ OPEN  {p:>5}/tcp  {svc}",
                                "success")
                except Exception:
                    pass
                finally:
                    with lock:
                        done[0] += 1
                        self.progress.set(done[0] / total)

        workers = []
        for port in port_list:
            if self._stop_flag:
                break
            t = threading.Thread(target=check, args=(port,), daemon=True)
            t.start()
            workers.append(t)

        for w in workers:
            w.join()

        self.out.println()
        if open_ports:
            self.out.println(
                f"  Resultado: {len(open_ports)} porta(s) abertas → "
                f"{sorted(open_ports)}", "accent")
        else:
            self.out.println("  Nenhuma porta aberta encontrada.", "warning")
        self.progress.set(1)


# ─────────────────────────────────────────────────────────────────
class DNSTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Domínio:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.host = ctk.CTkEntry(top, width=250, placeholder_text="google.com",
                                  font=FONT_MED)
        self.host.pack(side="left", padx=8)
        self.host.insert(0, "google.com")

        ctk.CTkLabel(top, text="Tipo:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.rtype = ctk.CTkComboBox(
            top, values=["A", "AAAA", "MX", "NS", "TXT", "CNAME",
                         "SOA", "PTR", "SRV", "ALL"], width=100,
            font=FONT_MED)
        self.rtype.pack(side="left", padx=8)
        self.rtype.set("A")

        ctk.CTkButton(top, text="▶  Resolver", width=120,
                       fg_color=COLORS["accent4"],
                       command=self._run).pack(side="left", padx=4)

        ctk.CTkButton(top, text="Reverse DNS", width=120,
                       fg_color=COLORS["sidebar"],
                       border_width=1, border_color=COLORS["border"],
                       command=self._reverse).pack(side="left", padx=4)

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)
        self.out.configure(state="disabled")

    def _run(self):
        threading.Thread(target=self._dns_thread, daemon=True).start()

    def _reverse(self):
        threading.Thread(target=self._rev_thread, daemon=True).start()

    def _dns_thread(self):
        host = self.host.get().strip()
        rtype = self.rtype.get()
        self.out.clear()
        self.out.header(f"DNS LOOKUP → {host} [{rtype}]")

        types = (["A","AAAA","MX","NS","TXT","CNAME","SOA"]
                 if rtype == "ALL" else [rtype])

        if DNS_OK:
            resolver = dns.resolver.Resolver()
            for t in types:
                try:
                    answers = resolver.resolve(host, t)
                    self.out.println(f"\n  ── {t} Records ──", "accent")
                    for rdata in answers:
                        self.out.println(f"    {rdata}", "success")
                except dns.resolver.NoAnswer:
                    self.out.println(f"  [{t}] Sem registros.", "dim")
                except dns.resolver.NXDOMAIN:
                    self.out.println(f"  [{t}] Domínio não existe.", "error")
                except Exception as e:
                    self.out.println(f"  [{t}] Erro: {e}", "error")
        else:
            # Fallback usando socket
            try:
                ip = socket.gethostbyname(host)
                self.out.println(f"  A  →  {ip}", "success")
                try:
                    infos = socket.getaddrinfo(host, None)
                    ips = set(i[4][0] for i in infos)
                    for i in ips:
                        self.out.println(f"  ADDR  →  {i}", "success")
                except Exception:
                    pass
            except Exception as e:
                self.out.println(f"  Erro: {e}", "error")
            self.out.println(
                "\n  [!] Instale dnspython para consultas completas.", "warning")

    def _rev_thread(self):
        host = self.host.get().strip()
        self.out.clear()
        self.out.header(f"REVERSE DNS → {host}")
        try:
            name, _, _ = socket.gethostbyaddr(host)
            self.out.println(f"  PTR  →  {name}", "success")
        except socket.herror as e:
            self.out.println(f"  Erro: {e}", "error")


# ─────────────────────────────────────────────────────────────────
class WhoisTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Domínio / IP:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.host = ctk.CTkEntry(top, width=280, placeholder_text="google.com",
                                  font=FONT_MED)
        self.host.pack(side="left", padx=8)
        self.host.insert(0, "google.com")

        ctk.CTkButton(top, text="▶  WHOIS", width=110,
                       fg_color=COLORS["warning"],
                       command=self._run).pack(side="left", padx=4)

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)
        self.out.configure(state="disabled")

    def _run(self):
        threading.Thread(target=self._whois_thread, daemon=True).start()

    def _whois_thread(self):
        host = self.host.get().strip()
        self.out.clear()
        self.out.header(f"WHOIS → {host}")

        # Try system whois first
        result = run_command(["whois", host])
        if "[ERRO]" not in result and result.strip():
            for line in result.splitlines():
                tag = ""
                low = line.lower()
                if any(k in low for k in ["registrar", "registrant", "name server"]):
                    tag = "accent"
                elif any(k in low for k in ["expir", "creat", "updat"]):
                    tag = "warning"
                self.out.println(line, tag)
        else:
            # Fallback: socket WHOIS
            try:
                tld = host.split(".")[-1]
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect(("whois.iana.org", 43))
                s.sendall((tld + "\r\n").encode())
                resp = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    resp += data
                s.close()

                # Get actual whois server
                whois_server = None
                for line in resp.decode(errors="replace").splitlines():
                    if "whois:" in line.lower():
                        whois_server = line.split()[-1]
                        break

                if whois_server:
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2.settimeout(10)
                    s2.connect((whois_server, 43))
                    s2.sendall((host + "\r\n").encode())
                    resp2 = b""
                    while True:
                        data = s2.recv(4096)
                        if not data:
                            break
                        resp2 += data
                    s2.close()
                    self.out.println(resp2.decode(errors="replace"))
                else:
                    self.out.println(resp.decode(errors="replace"))
            except Exception as e:
                self.out.println(f"[ERRO] {e}", "error")
                self.out.println(
                    "\nDica: instale 'whois' no sistema.", "dim")


# ─────────────────────────────────────────────────────────────────
class InterfacesTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkButton(top, text="↺  Atualizar", width=130,
                       fg_color=COLORS["accent2"],
                       command=self._refresh).pack(side="left", padx=4)

        ctk.CTkButton(top, text="Rota Padrão", width=130,
                       fg_color=COLORS["sidebar"],
                       border_width=1, border_color=COLORS["border"],
                       command=self._routes).pack(side="left", padx=4)

        ctk.CTkButton(top, text="Tabela ARP", width=130,
                       fg_color=COLORS["sidebar"],
                       border_width=1, border_color=COLORS["border"],
                       command=self._arp).pack(side="left", padx=4)

        ctk.CTkButton(top, text="Conexões Ativas", width=140,
                       fg_color=COLORS["sidebar"],
                       border_width=1, border_color=COLORS["border"],
                       command=self._connections).pack(side="left", padx=4)

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)
        self.out.configure(state="disabled")

        self._refresh()

    def _refresh(self):
        self.out.clear()
        self.out.header("INTERFACES DE REDE")

        if PSUTIL_OK:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface, addr_list in addrs.items():
                stat = stats.get(iface)
                status = "UP" if (stat and stat.isup) else "DOWN"
                spd = f"{stat.speed}Mbps" if stat and stat.speed else "?"
                tag = "success" if status == "UP" else "error"
                self.out.println(f"\n  ┌─ {iface}  [{status}]  {spd}", tag)
                for addr in addr_list:
                    fam_map = {
                        socket.AF_INET:  "IPv4",
                        socket.AF_INET6: "IPv6",
                        -1:              "MAC ",
                    }
                    # psutil AF; import the helper module without rebinding
                    # the name `psutil` (avoid UnboundLocalError).
                    try:
                        from psutil import _common
                        if hasattr(_common, 'AF_LINK'):
                            fam_map[_common.AF_LINK] = "MAC "
                    except Exception:
                        pass
                    fname = fam_map.get(addr.family, str(addr.family))
                    nm = f"  Mask: {addr.netmask}" if addr.netmask else ""
                    bc = f"  Bcast: {addr.broadcast}" if addr.broadcast else ""
                    self.out.println(
                        f"  │   {fname}: {addr.address}{nm}{bc}", "dim")
        else:
            # fallback
            out = run_command(["ip", "addr"] if sys.platform != "win32"
                              else ["ipconfig", "/all"])
            self.out.println(out)

    def _routes(self):
        self.out.clear()
        self.out.header("TABELA DE ROTAS")
        cmd = (["route", "print"] if sys.platform == "win32"
               else ["ip", "route"])
        self.out.println(run_command(cmd))

    def _arp(self):
        self.out.clear()
        self.out.header("TABELA ARP")
        cmd = (["arp", "-a"] if sys.platform == "win32"
               else ["arp", "-n"])
        self.out.println(run_command(cmd))

    def _connections(self):
        self.out.clear()
        self.out.header("CONEXÕES TCP ATIVAS")

        if PSUTIL_OK:
            conns = psutil.net_connections(kind="tcp")
            self.out.println(
                f"  {'Proto':<6} {'Local':<28} {'Remoto':<28} "
                f"{'Status':<14} {'PID'}", "accent")
            self.out.println("  " + "─" * 85, "dim")
            for c in sorted(conns, key=lambda x: x.status):
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                tag = ("success" if c.status == "ESTABLISHED"
                       else "dim" if c.status in ("LISTEN", "TIME_WAIT")
                       else "")
                self.out.println(
                    f"  {'TCP':<6} {laddr:<28} {raddr:<28} "
                    f"{c.status:<14} {c.pid or '?'}", tag)
        else:
            cmd = (["netstat", "-ano"] if sys.platform == "win32"
                   else ["ss", "-tuln"])
            self.out.println(run_command(cmd))


# ─────────────────────────────────────────────────────────────────
class BandwidthTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._running = False
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Interface:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")

        ifaces = ["Todas"]
        if PSUTIL_OK:
            ifaces += list(psutil.net_if_stats().keys())
        self.iface = ctk.CTkComboBox(top, values=ifaces, width=160,
                                      font=FONT_MED)
        self.iface.set("Todas")
        self.iface.pack(side="left", padx=8)

        self.btn_start = ctk.CTkButton(
            top, text="▶  Iniciar Monitor", width=150,
            fg_color=COLORS["accent2"], command=self._start)
        self.btn_start.pack(side="left", padx=4)

        ctk.CTkButton(top, text="⏹  Parar", width=100,
                       fg_color=COLORS["accent3"],
                       command=self._stop).pack(side="left", padx=4)

        # Stats cards row
        cards = ctk.CTkFrame(self, fg_color="transparent")
        cards.pack(fill="x", padx=10, pady=4)
        for i in range(4):
            cards.columnconfigure(i, weight=1)

        self.lbl_rx = self._stat_card(cards, "↓ Download", 0)
        self.lbl_tx = self._stat_card(cards, "↑ Upload", 1)
        self.lbl_rx_total = self._stat_card(cards, "Total RX", 2)
        self.lbl_tx_total = self._stat_card(cards, "Total TX", 3)

        self.out = OutputBox(self, height=330)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)
        self.out.configure(state="disabled")

    def _stat_card(self, parent, title, col):
        f = Card(parent, title=title)
        f.grid(row=0, column=col, padx=6, pady=4, sticky="ew")
        lbl = ctk.CTkLabel(f, text="─ ─", font=("Segoe UI", 18, "bold"),
                            text_color=COLORS["accent"])
        lbl.pack(pady=(0, 10))
        return lbl

    def _fmt(self, b: float) -> str:
        for u in ["B/s", "KB/s", "MB/s", "GB/s"]:
            if b < 1024:
                return f"{b:.1f} {u}"
            b /= 1024
        return f"{b:.1f} TB/s"

    def _fmt_total(self, b: float) -> str:
        for u in ["B", "KB", "MB", "GB", "TB"]:
            if b < 1024:
                return f"{b:.2f} {u}"
            b /= 1024
        return f"{b:.2f} PB"

    def _start(self):
        if not PSUTIL_OK:
            self.out.clear()
            self.out.println("[ERRO] psutil não instalado.", "error")
            return
        self._running = True
        threading.Thread(target=self._monitor_thread, daemon=True).start()

    def _stop(self):
        self._running = False

    def _monitor_thread(self):
        self.out.clear()
        self.out.header("MONITOR DE BANDA")
        self.out.println(f"  {'Hora':<10} {'↓ RX/s':<16} {'↑ TX/s':<16} "
                         f"{'Total RX':<16} {'Total TX'}", "accent")
        self.out.println("  " + "─" * 70, "dim")

        prev = psutil.net_io_counters(pernic=True)
        while self._running:
            time.sleep(1)
            curr = psutil.net_io_counters(pernic=True)
            sel = self.iface.get()

            rx = tx = rx_t = tx_t = 0
            for iface, c in curr.items():
                if sel != "Todas" and iface != sel:
                    continue
                p = prev.get(iface)
                if p:
                    rx += c.bytes_recv - p.bytes_recv
                    tx += c.bytes_sent - p.bytes_sent
                rx_t += c.bytes_recv
                tx_t += c.bytes_sent

            self.lbl_rx.configure(text=self._fmt(rx))
            self.lbl_tx.configure(text=self._fmt(tx))
            self.lbl_rx_total.configure(text=self._fmt_total(rx_t))
            self.lbl_tx_total.configure(text=self._fmt_total(tx_t))

            tag = ("error" if rx > 5_000_000 or tx > 5_000_000
                   else "success" if rx > 0 or tx > 0 else "dim")
            self.out.println(
                f"  {ts():<10} {self._fmt(rx):<16} {self._fmt(tx):<16} "
                f"{self._fmt_total(rx_t):<16} {self._fmt_total(tx_t)}", tag)
            prev = curr


# ─────────────────────────────────────────────────────────────────
class HTTPTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="URL:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.url = ctk.CTkEntry(top, width=350,
                                 placeholder_text="https://example.com",
                                 font=FONT_MED)
        self.url.pack(side="left", padx=8)
        self.url.insert(0, "https://example.com")

        self.method = ctk.CTkComboBox(
            top, values=["GET","HEAD","POST","OPTIONS"], width=100,
            font=FONT_MED)
        self.method.set("GET")
        self.method.pack(side="left", padx=4)

        ctk.CTkButton(top, text="▶  Enviar", width=110,
                       fg_color=COLORS["accent"],
                       command=self._run).pack(side="left", padx=4)

        ctk.CTkButton(top, text="SSL/TLS Info", width=120,
                       fg_color=COLORS["sidebar"],
                       border_width=1, border_color=COLORS["border"],
                       command=self._ssl).pack(side="left", padx=4)

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)
        self.out.configure(state="disabled")

    def _run(self):
        threading.Thread(target=self._http_thread, daemon=True).start()

    def _ssl(self):
        threading.Thread(target=self._ssl_thread, daemon=True).start()

    def _http_thread(self):
        url = self.url.get().strip()
        method = self.method.get()
        self.out.clear()
        self.out.header(f"HTTP {method} → {url}")

        if REQUESTS_OK:
            try:
                t0 = time.time()
                r = requests.request(method, url, timeout=10,
                                     allow_redirects=True,
                                     verify=False)
                elapsed = (time.time() - t0) * 1000

                tag = ("success" if r.status_code < 400
                       else "warning" if r.status_code < 500
                       else "error")
                self.out.println(
                    f"  HTTP/{r.raw.version/10:.1f}  "
                    f"{r.status_code} {r.reason}  ({elapsed:.0f}ms)", tag)
                self.out.println()
                self.out.println("  ── Headers ──", "accent")
                for k, v in r.headers.items():
                    self.out.println(f"  {k}: {v}", "dim")

                if method != "HEAD" and r.text:
                    self.out.println()
                    self.out.println("  ── Body (primeiros 2KB) ──", "accent")
                    self.out.println("  " + r.text[:2048])
            except Exception as e:
                self.out.println(f"  Erro: {e}", "error")
        else:
            # Fallback com socket/http.client
            try:
                import urllib.request
                import urllib.error
                t0 = time.time()
                req = urllib.request.Request(url, method=method)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    elapsed = (time.time() - t0) * 1000
                    self.out.println(
                        f"  Status: {resp.status} {resp.reason}  "
                        f"({elapsed:.0f}ms)", "success")
                    self.out.println("\n  ── Headers ──", "accent")
                    for k, v in resp.headers.items():
                        self.out.println(f"  {k}: {v}", "dim")
            except Exception as e:
                self.out.println(f"  Erro: {e}", "error")
            self.out.println(
                "\n  [!] Instale requests para funcionalidades completas.",
                "warning")

    def _ssl_thread(self):
        import ssl
        url = self.url.get().strip()
        host = re.sub(r"https?://", "", url).split("/")[0].split(":")[0]
        self.out.clear()
        self.out.header(f"SSL/TLS → {host}")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    self.out.println(
                        f"  Protocolo  : {ssock.version()}", "success")
                    self.out.println(
                        f"  Cipher     : {ssock.cipher()[0]}")
                    self.out.println(
                        f"  Bits       : {ssock.cipher()[2]}")
                    subj = dict(x[0] for x in cert["subject"])
                    self.out.println(
                        f"\n  ── Certificado ──", "accent")
                    self.out.println(
                        f"  CN         : {subj.get('commonName', '?')}")
                    self.out.println(
                        f"  Org        : {subj.get('organizationName', '?')}")
                    self.out.println(
                        f"  Válido até : {cert.get('notAfter', '?')}",
                        "warning")
                    sans = cert.get("subjectAltName", [])
                    if sans:
                        self.out.println(
                            f"\n  SANs:", "accent")
                        for _, name in sans[:10]:
                            self.out.println(f"    {name}", "dim")
        except Exception as e:
            self.out.println(f"  Erro: {e}", "error")


# ─────────────────────────────────────────────────────────────────
class SubnetTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="CIDR / IP:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.cidr = ctk.CTkEntry(top, width=200,
                                  placeholder_text="192.168.1.0/24",
                                  font=FONT_MED)
        self.cidr.pack(side="left", padx=8)
        self.cidr.insert(0, "192.168.1.0/24")

        ctk.CTkButton(top, text="Calcular", width=110,
                       fg_color=COLORS["accent2"],
                       command=self._run).pack(side="left", padx=4)

        ctk.CTkButton(top, text="Subnets /26 /27 /28", width=160,
                       fg_color=COLORS["sidebar"],
                       border_width=1, border_color=COLORS["border"],
                       command=self._subnets).pack(side="left", padx=4)

        ctk.CTkButton(top, text="IP → Binário", width=130,
                       fg_color=COLORS["sidebar"],
                       border_width=1, border_color=COLORS["border"],
                       command=self._binary).pack(side="left", padx=4)

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)
        self.out.configure(state="disabled")

    def _run(self):
        v = self.cidr.get().strip()
        self.out.clear()
        self.out.header(f"SUBNET CALCULATOR → {v}")
        try:
            if "/" not in v:
                v += "/24"
            net = ipaddress.ip_network(v, strict=False)
            host_ip = ipaddress.ip_address(v.split("/")[0])

            self.out.println(f"  Rede             : {net.network_address}", "accent")
            self.out.println(f"  Broadcast        : {net.broadcast_address}", "warning")
            self.out.println(f"  Máscara          : {net.netmask}")
            self.out.println(f"  Máscara Wildcard : {net.hostmask}")
            self.out.println(f"  Prefixo          : /{net.prefixlen}")
            self.out.println(f"  Total de IPs     : {net.num_addresses:,}")
            hosts = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
            self.out.println(f"  Hosts utilizáveis: {max(0, hosts):,}", "success")
            self.out.println(f"  Versão           : IPv{net.version}")
            self.out.println(f"  Privada          : {'Sim' if net.is_private else 'Não'}")

            if net.num_addresses > 1:
                hosts_iter = list(net.hosts())
                if hosts_iter:
                    self.out.println(
                        f"\n  Primeiro host    : {hosts_iter[0]}", "success")
                    self.out.println(
                        f"  Último host      : {hosts_iter[-1]}", "success")

            # Check if input IP is in network
            if host_ip in net:
                self.out.println(
                    f"\n  ✓ {host_ip} está na rede {net}", "success")
        except ValueError as e:
            self.out.println(f"  Erro: {e}", "error")

    def _subnets(self):
        v = self.cidr.get().strip()
        self.out.clear()
        self.out.header(f"SUBDIVISÃO → {v}")
        try:
            if "/" not in v:
                v += "/24"
            net = ipaddress.ip_network(v, strict=False)
            for new_prefix in [26, 27, 28, 29, 30]:
                if new_prefix <= net.prefixlen:
                    continue
                subs = list(net.subnets(new_prefix=new_prefix))
                self.out.println(
                    f"\n  /{new_prefix}  →  {len(subs)} subnets  "
                    f"({max(0, 2**(32-new_prefix)-2)} hosts/sub)", "accent")
                for i, s in enumerate(subs[:8]):
                    self.out.println(
                        f"    {str(s):<22}  "
                        f"{s.network_address} → {s.broadcast_address}", "dim")
                if len(subs) > 8:
                    self.out.println(
                        f"    ... e mais {len(subs)-8}", "dim")
        except ValueError as e:
            self.out.println(f"  Erro: {e}", "error")

    def _binary(self):
        v = self.cidr.get().strip().split("/")[0]
        self.out.clear()
        self.out.header(f"IP → BINÁRIO → {v}")
        try:
            ip = ipaddress.ip_address(v)
            packed = int(ip)
            octets = []
            for i in range(3, -1, -1):
                octets.append((packed >> (i * 8)) & 0xFF)
            self.out.println(f"\n  IP (decimal) : {v}", "accent")
            self.out.println(
                f"  IP (binário) : "
                f"{'  '.join(f'{o:08b}' for o in octets)}", "success")
            self.out.println(
                f"  IP (hex)     : "
                f"{'  '.join(f'{o:02X}' for o in octets)}", "warning")
            self.out.println(f"  IP (int)     : {int(ip):,}")

            self.out.println("\n  Octetos:", "dim")
            for i, o in enumerate(octets, 1):
                self.out.println(
                    f"    Octeto {i}: {o:>3}  =  {o:08b}  =  0x{o:02X}", "dim")
        except ValueError as e:
            self.out.println(f"  Erro: {e}", "error")


# ─────────────────────────────────────────────────────────────────
class GeoIPTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="IP:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.ip = ctk.CTkEntry(top, width=220,
                                placeholder_text="8.8.8.8",
                                font=FONT_MED)
        self.ip.pack(side="left", padx=8)
        self.ip.insert(0, "8.8.8.8")

        ctk.CTkButton(top, text="▶  Geolocalizar", width=140,
                       fg_color=COLORS["accent4"],
                       command=self._run).pack(side="left", padx=4)

        ctk.CTkButton(top, text="Meu IP público", width=140,
                       fg_color=COLORS["sidebar"],
                       border_width=1, border_color=COLORS["border"],
                       command=self._myip).pack(side="left", padx=4)

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)
        self.out.configure(state="disabled")

    def _run(self):
        threading.Thread(target=self._geo_thread, daemon=True).start()

    def _myip(self):
        threading.Thread(target=self._myip_thread, daemon=True).start()

    def _query_geo(self, ip: str) -> dict | None:
        try:
            if REQUESTS_OK:
                r = requests.get(f"http://ip-api.com/json/{ip}",
                                 timeout=8)
                return r.json()
            else:
                import urllib.request
                url = f"http://ip-api.com/json/{ip}"
                with urllib.request.urlopen(url, timeout=8) as resp:
                    return json.loads(resp.read())
        except Exception:
            return None

    def _geo_thread(self):
        ip = self.ip.get().strip()
        self.out.clear()
        self.out.header(f"GEOIP → {ip}")

        data = self._query_geo(ip)
        if not data:
            self.out.println("  [ERRO] Sem conexão ou serviço indisponível.",
                             "error")
            return

        if data.get("status") == "fail":
            self.out.println(f"  Erro: {data.get('message','?')}", "error")
            return

        fields = [
            ("IP",         "query"),
            ("País",       "country"),
            ("Código",     "countryCode"),
            ("Região",     "regionName"),
            ("Cidade",     "city"),
            ("CEP",        "zip"),
            ("Timezone",   "timezone"),
            ("Latitude",   "lat"),
            ("Longitude",  "lon"),
            ("ISP",        "isp"),
            ("Org",        "org"),
            ("AS",         "as"),
        ]
        for label, key in fields:
            val = data.get(key, "?")
            tag = "accent" if key == "query" else ""
            self.out.println(f"  {label:<12}: {val}", tag)

    def _myip_thread(self):
        self.out.clear()
        self.out.header("MEU IP PÚBLICO")
        try:
            if REQUESTS_OK:
                r = requests.get("https://api.ipify.org?format=json",
                                  timeout=8)
                ip = r.json().get("ip", "?")
            else:
                import urllib.request
                with urllib.request.urlopen(
                        "https://api.ipify.org", timeout=8) as resp:
                    ip = resp.read().decode()
            self.out.println(f"  IP Público: {ip}", "success")
            self.ip.delete(0, "end")
            self.ip.insert(0, ip)

            # Also geolocate
            self.out.println()
            data = self._query_geo(ip)
            if data and data.get("status") != "fail":
                self.out.println(
                    f"  País   : {data.get('country','?')}  "
                    f"({data.get('countryCode','?')})", "accent")
                self.out.println(
                    f"  Cidade : {data.get('city','?')}, "
                    f"{data.get('regionName','?')}")
                self.out.println(
                    f"  ISP    : {data.get('isp','?')}", "dim")
        except Exception as e:
            self.out.println(f"  Erro: {e}", "error")


# ─────────────────────────────────────────────────────────────────
class WakeOnLANTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="MAC:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.mac = ctk.CTkEntry(top, width=200,
                                 placeholder_text="AA:BB:CC:DD:EE:FF",
                                 font=FONT_MED)
        self.mac.pack(side="left", padx=8)

        ctk.CTkLabel(top, text="Broadcast:", font=FONT_MED,
                     text_color=COLORS["text"]).pack(side="left")
        self.bcast = ctk.CTkEntry(top, width=160,
                                   placeholder_text="192.168.1.255",
                                   font=FONT_MED)
        self.bcast.pack(side="left", padx=8)
        self.bcast.insert(0, "255.255.255.255")

        ctk.CTkButton(top, text="⚡ Enviar WoL", width=130,
                       fg_color=COLORS["warning"],
                       command=self._run).pack(side="left", padx=4)

        self.out = OutputBox(self, height=200)
        self.out.pack(fill="x", padx=10, pady=6)
        self.out.configure(state="disabled")

        # Info
        info = Card(self, title="ℹ  Wake-on-LAN")
        info.pack(fill="x", padx=10, pady=4)
        ctk.CTkLabel(
            info,
            text=(
                "WoL envia um 'Magic Packet' UDP (porta 9) ao endereço MAC "
                "da máquina alvo.\n"
                "O computador deve ter WoL habilitado na BIOS/UEFI e na "
                "configuração da placa de rede.\n"
                "O broadcast deve ser o da sub-rede local (ex: 192.168.1.255)."
            ),
            font=FONT_SMALL, text_color=COLORS["text_dim"],
            justify="left", wraplength=700
        ).pack(anchor="w", padx=14, pady=(0, 10))

    def _run(self):
        mac = self.mac.get().strip().replace("-", ":").replace(".", ":")
        bcast = self.bcast.get().strip() or "255.255.255.255"
        self.out.clear()
        self.out.header(f"WAKE-ON-LAN → {mac}")

        try:
            mac_bytes = bytes(int(b, 16) for b in mac.split(":"))
            if len(mac_bytes) != 6:
                raise ValueError("MAC inválido")
            magic = b'\xff' * 6 + mac_bytes * 16
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.sendto(magic, (bcast, 9))
            self.out.println(
                f"  ✓ Magic Packet enviado para {mac} via {bcast}:9",
                "success")
            self.out.println(f"  Tamanho: {len(magic)} bytes")
        except Exception as e:
            self.out.println(f"  Erro: {e}", "error")


# ─────────────────────────────────────────────────────────────────
class SpeedTestTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkButton(top, text="▶  Iniciar Speedtest", width=160,
                       fg_color=COLORS["accent"],
                       command=self._run).pack(side="left", padx=4)

        self.out = OutputBox(self, height=180)
        self.out.pack(fill="x", padx=10, pady=6)
        self.out.configure(state="disabled")

        # Result cards
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", padx=10, pady=4)
        for i in range(3):
            cards_frame.columnconfigure(i, weight=1)

        self.lbl_down = self._card(cards_frame, "↓ Download", 0)
        self.lbl_up   = self._card(cards_frame, "↑ Upload", 1)
        self.lbl_lat  = self._card(cards_frame, "⏱ Latência", 2)

        info = Card(self, title="ℹ  Como funciona")
        info.pack(fill="x", padx=10, pady=4)
        ctk.CTkLabel(
            info,
            text=(
                "Speedtest básico: baixa um arquivo de teste e mede a taxa.\n"
                "Para resultados precisos, instale: pip install speedtest-cli"
            ),
            font=FONT_SMALL, text_color=COLORS["text_dim"],
            justify="left"
        ).pack(anchor="w", padx=14, pady=(0, 10))

    def _card(self, parent, title, col):
        f = Card(parent, title=title)
        f.grid(row=0, column=col, padx=6, pady=4, sticky="ew")
        lbl = ctk.CTkLabel(f, text="─", font=("Segoe UI", 20, "bold"),
                            text_color=COLORS["accent"])
        lbl.pack(pady=(0, 10))
        return lbl

    def _run(self):
        threading.Thread(target=self._speed_thread, daemon=True).start()

    def _speed_thread(self):
        self.out.clear()
        self.out.header("SPEEDTEST")

        # Try speedtest-cli first
        try:
            import speedtest as st_module
            self.out.println("  Obtendo servidores...", "dim")
            st = st_module.Speedtest()
            st.get_best_server()
            self.out.println("  Testando download...", "dim")
            dl = st.download() / 1_000_000
            self.out.println("  Testando upload...", "dim")
            ul = st.upload() / 1_000_000
            lat = st.results.ping
            self.lbl_down.configure(text=f"{dl:.1f} Mbps")
            self.lbl_up.configure(text=f"{ul:.1f} Mbps")
            self.lbl_lat.configure(text=f"{lat:.1f} ms")
            self.out.println(f"  Download : {dl:.2f} Mbps", "success")
            self.out.println(f"  Upload   : {ul:.2f} Mbps", "success")
            self.out.println(f"  Latência : {lat:.1f} ms", "accent")
            return
        except ImportError:
            pass

        # Fallback: HTTP download test
        test_urls = [
            ("Cloudflare 10MB",
             "https://speed.cloudflare.com/__down?bytes=10000000"),
            ("Fast.com probe",
             "https://api.fast.com/netflix/speedtest/v2"),
        ]

        for name, url in test_urls:
            self.out.println(f"  Testando via {name}...", "dim")
            try:
                if REQUESTS_OK:
                    t0 = time.time()
                    r = requests.get(url, timeout=15, stream=True)
                    total = 0
                    for chunk in r.iter_content(chunk_size=65536):
                        total += len(chunk)
                    elapsed = time.time() - t0
                    mbps = (total * 8) / elapsed / 1_000_000
                    self.lbl_down.configure(text=f"~{mbps:.1f} Mbps")
                    self.out.println(
                        f"  Download ≈ {mbps:.2f} Mbps  "
                        f"({total/1e6:.1f} MB em {elapsed:.1f}s)", "success")
                    break
                else:
                    import urllib.request
                    t0 = time.time()
                    with urllib.request.urlopen(url, timeout=15) as resp:
                        data = resp.read()
                    elapsed = time.time() - t0
                    mbps = (len(data) * 8) / elapsed / 1_000_000
                    self.lbl_down.configure(text=f"~{mbps:.1f} Mbps")
                    self.out.println(
                        f"  Download ≈ {mbps:.2f} Mbps", "success")
                    break
            except Exception as e:
                self.out.println(f"  {name}: {e}", "error")
                continue

        # Latency test
        self.out.println("\n  Testando latência...", "dim")
        lats = []
        for _ in range(5):
            t0 = time.time()
            try:
                s = socket.create_connection(("8.8.8.8", 53), timeout=2)
                s.close()
                lats.append((time.time() - t0) * 1000)
            except Exception:
                pass
        if lats:
            avg = sum(lats) / len(lats)
            self.lbl_lat.configure(text=f"{avg:.1f} ms")
            self.out.println(
                f"  Latência  ≈ {avg:.1f} ms (avg {len(lats)} amostras)",
                "accent")


# ─────────────────────────────────────────────────────────────────
class NetstatTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        for label, cmd, color in [
            ("TCP", self._tcp, COLORS["accent"]),
            ("UDP", self._udp, COLORS["accent2"]),
            ("Listen", self._listen, COLORS["accent4"]),
            ("Estatísticas", self._stats, COLORS["warning"]),
            ("Processos", self._proc, COLORS["sidebar"]),
        ]:
            ctk.CTkButton(
                top, text=label, width=110, fg_color=color,
                border_width=1 if color == COLORS["sidebar"] else 0,
                border_color=COLORS["border"],
                command=cmd).pack(side="left", padx=3)

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)
        self.out.configure(state="disabled")

    def _tcp(self):
        threading.Thread(target=self._run,
                         args=("TCP CONNECTIONS",), daemon=True).start()

    def _udp(self):
        threading.Thread(target=self._run,
                         args=("UDP",), daemon=True).start()

    def _listen(self):
        threading.Thread(target=self._run,
                         args=("LISTENING",), daemon=True).start()

    def _stats(self):
        threading.Thread(target=self._run,
                         args=("STATISTICS",), daemon=True).start()

    def _proc(self):
        threading.Thread(target=self._run,
                         args=("PROCESSES",), daemon=True).start()

    def _run(self, mode: str):
        self.out.clear()
        self.out.header(f"NETSTAT → {mode}")

        if PSUTIL_OK and mode != "STATISTICS":
            kind_map = {
                "TCP CONNECTIONS": "tcp",
                "UDP": "udp",
                "LISTENING": "inet",
                "PROCESSES": "inet",
            }
            kind = kind_map.get(mode, "inet")
            conns = psutil.net_connections(kind=kind)

            self.out.println(
                f"  {'Proto':<6} {'Local':<30} {'Remoto':<30} "
                f"{'Status':<16} {'PID':<7} {'Processo'}", "accent")
            self.out.println("  " + "─" * 100, "dim")

            for c in sorted(conns, key=lambda x: (x.status, x.laddr)):
                if mode == "LISTENING" and c.status != "LISTEN":
                    continue
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                pid = c.pid or "?"
                try:
                    proc_name = (psutil.Process(c.pid).name()
                                 if c.pid else "-")
                except Exception:
                    proc_name = "-"

                tag = ("success" if c.status == "ESTABLISHED"
                       else "warning" if c.status == "LISTEN"
                       else "dim")
                self.out.println(
                    f"  {proto:<6} {laddr:<30} {raddr:<30} "
                    f"{c.status or '-':<16} {str(pid):<7} {proc_name}", tag)
        else:
            if sys.platform == "win32":
                cmds = {
                    "TCP CONNECTIONS": ["netstat", "-ano", "-p", "TCP"],
                    "UDP": ["netstat", "-ano", "-p", "UDP"],
                    "LISTENING": ["netstat", "-an"],
                    "STATISTICS": ["netstat", "-s"],
                    "PROCESSES": ["netstat", "-b"],
                }
            else:
                cmds = {
                    "TCP CONNECTIONS": ["ss", "-tnp"],
                    "UDP": ["ss", "-unp"],
                    "LISTENING": ["ss", "-tlnp"],
                    "STATISTICS": ["ss", "-s"],
                    "PROCESSES": ["ss", "-tp"],
                }
            self.out.println(run_command(cmds.get(mode, ["ss", "-a"])))

# ================== NETWORK DISCOVERY ==================
class NetworkDiscoveryTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._stop_flag = False
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Rede (CIDR):", font=FONT_MED).pack(side="left")
        self.cidr = ctk.CTkEntry(top, width=200, placeholder_text="192.168.1.0/24", font=FONT_MED)
        self.cidr.pack(side="left", padx=8)
        self.cidr.insert(0, "192.168.1.0/24")

        ctk.CTkLabel(top, text="Timeout (s):", font=FONT_MED).pack(side="left")
        self.timeout = ctk.CTkEntry(top, width=60, font=FONT_MED)
        self.timeout.pack(side="left", padx=8)
        self.timeout.insert(0, "0.5")

        self.use_arp = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(top, text="Usar ARP (mais rápido)", variable=self.use_arp,
                        font=FONT_SMALL).pack(side="left", padx=8)

        self.btn = ctk.CTkButton(top, text="▶  Descobrir", width=120,
                                  fg_color=COLORS["accent"], command=self._run)
        self.btn.pack(side="left", padx=4)

        ctk.CTkButton(top, text="✖ Parar", width=90,
                      fg_color=COLORS["accent3"], command=self._stop).pack(side="left", padx=4)

        self.progress = ctk.CTkProgressBar(self, mode="determinate")
        self.progress.set(0)
        self.progress.pack(fill="x", padx=10, pady=5)

        self.out = OutputBox(self, height=400)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)

    def _stop(self):
        self._stop_flag = True

    def _run(self):
        self._stop_flag = False
        threading.Thread(target=self._discovery_thread, daemon=True).start()

    def _discovery_thread(self):
        cidr_str = self.cidr.get().strip()
        timeout = float(self.timeout.get() or 0.5)
        use_arp = self.use_arp.get()

        try:
            network = ipaddress.ip_network(cidr_str, strict=False)
        except Exception as e:
            self.out.clear()
            self.out.println(f"[ERRO] CIDR inválido: {e}", "error")
            return

        self.out.clear()
        self.out.header(f"DISCOVERY → {cidr_str}")
        self.out.println(f"  Varrendo {network.num_addresses} endereços...", "dim")
        self.progress.set(0)

        hosts = []
        lock = threading.Lock()
        total = network.num_addresses
        done = 0

        # Tenta ARP primeiro se solicitado e se estiver em rede local
        if use_arp and network.prefixlen >= 16:  # só para redes pequenas/médias
            try:
                import subprocess
                # comando arp-scan se disponível (Linux)
                if sys.platform != "win32":
                    result = subprocess.run(["arp-scan", "--localnet"], capture_output=True, text=True, timeout=30)
                    for line in result.stdout.splitlines():
                        if re.match(r"^\d+\.\d+\.\d+\.\d+\s+([a-fA-F0-9:]{17})", line):
                            parts = line.split()
                            ip = parts[0]
                            mac = parts[1]
                            vendor = self._get_vendor(mac)
                            hosts.append((ip, mac, vendor))
                            self.out.println(f"  {ip:<15} {mac}  {vendor}", "success")
            except:
                pass

        if not hosts:
            # Fallback para ping
            sem = threading.Semaphore(100)  # máximo 100 threads simultâneas

            def ping(ip):
                nonlocal done
                if self._stop_flag:
                    return
                with sem:
                    try:
                        # Usa ping do sistema ou socket ICMP (requer privilégios)
                        # Vamos usar socket TCP na porta 80 como fallback (ping TCP)
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(timeout)
                        result = sock.connect_ex((str(ip), 80))
                        sock.close()
                        if result == 0:
                            # Obter MAC via ARP (se possível)
                            mac = self._get_mac_arp(ip)
                            vendor = self._get_vendor(mac) if mac else ""
                            with lock:
                                hosts.append((str(ip), mac or "?", vendor))
                                self.out.println(f"  {ip:<15} {mac or '?':<17} {vendor}", "success")
                    except:
                        pass
                    finally:
                        with lock:
                            done += 1
                            self.progress.set(done / total)

            threads = []
            for ip in network.hosts():
                if self._stop_flag:
                    break
                t = threading.Thread(target=ping, args=(ip,), daemon=True)
                t.start()
                threads.append(t)
                # Pequeno delay para não sobrecarregar
                time.sleep(0.01)

            for t in threads:
                t.join()

        self.out.println()
        self.out.println(f"  Total de dispositivos encontrados: {len(hosts)}", "accent")
        self.progress.set(1)

    def _get_mac_arp(self, ip):
        """Tenta obter o MAC via tabela ARP (Linux/Windows)"""
        try:
            if sys.platform == "win32":
                result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if ip in line:
                        parts = line.split()
                        # Formato Windows: IP           MAC           Tipo
                        if len(parts) >= 2:
                            return parts[1].replace('-', ':')
            else:
                result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if ip in line and "ether" in line:
                        parts = line.split()
                        for i, p in enumerate(parts):
                            if p == "ether":
                                return parts[i+1]
        except:
            pass
        return ""

    def _get_vendor(self, mac):
        if not mac or mac == "?":
            return ""
        try:
            from mac_vendor_lookup import MacLookup
            return MacLookup().lookup(mac)
        except:
            return ""

# ================== PACKET SNIFFER ==================
class PacketSnifferTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._sniffing = False
        self._sniffer_thread = None
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Interface:", font=FONT_MED).pack(side="left")
        self.iface = ctk.CTkComboBox(top, values=self._get_interfaces(), width=150, font=FONT_MED)
        self.iface.pack(side="left", padx=8)

        ctk.CTkLabel(top, text="Filtro:", font=FONT_MED).pack(side="left")
        self.filter = ctk.CTkEntry(top, width=200, placeholder_text="tcp or udp", font=FONT_MED)
        self.filter.pack(side="left", padx=8)

        self.btn_start = ctk.CTkButton(top, text="▶  Iniciar", width=100,
                                        fg_color=COLORS["accent2"], command=self._start)
        self.btn_start.pack(side="left", padx=4)
        self.btn_stop = ctk.CTkButton(top, text="⏹  Parar", width=100,
                                       fg_color=COLORS["accent3"], command=self._stop, state="disabled")
        self.btn_stop.pack(side="left", padx=4)

        self.stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.stats_frame.pack(fill="x", padx=10, pady=4)
        self.lbl_total = ctk.CTkLabel(self.stats_frame, text="Pacotes: 0", font=FONT_BOLD)
        self.lbl_total.pack(side="left", padx=10)

        self.out = OutputBox(self, height=400)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)

        self.packet_count = 0

    def _get_interfaces(self):
        try:
            from scapy.interfaces import get_working_ifaces
            return [iface.name for iface in get_working_ifaces()]
        except:
            return ["eth0", "wlan0", "lo"]

    def _start(self):
        self._sniffing = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.out.clear()
        self.out.header(f"SNIFFER → {self.iface.get()}  Filtro: {self.filter.get()}")
        self.packet_count = 0
        self._sniffer_thread = threading.Thread(target=self._sniff_thread, daemon=True)
        self._sniffer_thread.start()

    def _stop(self):
        self._sniffing = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def _sniff_thread(self):
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
        except ImportError:
            self.out.println("[ERRO] Scapy não instalado. Instale com: pip install scapy", "error")
            self._stop()
            return

        def process_packet(pkt):
            if not self._sniffing:
                return True  # stop sniff
            self.packet_count += 1
            self.lbl_total.configure(text=f"Pacotes: {self.packet_count}")
            # Sumário
            if IP in pkt:
                ip = pkt[IP]
                proto = ""
                if TCP in pkt:
                    proto = f"TCP {pkt[TCP].sport}->{pkt[TCP].dport}"
                elif UDP in pkt:
                    proto = f"UDP {pkt[UDP].sport}->{pkt[UDP].dport}"
                elif ICMP in pkt:
                    proto = "ICMP"
                line = f"{ip.src} -> {ip.dst}  {proto}"
                self.out.println(line, "dim")
            return False  # continue sniff

        try:
            sniff(iface=self.iface.get(), filter=self.filter.get() or None,
                  prn=process_packet, stop_filter=lambda x: not self._sniffing)
        except Exception as e:
            self.out.println(f"[ERRO] {e}", "error")
        finally:
            self._sniffing = False
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")

# ================== SNMP SCANNER ==================
class SNMPTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Host:", font=FONT_MED).pack(side="left")
        self.host = ctk.CTkEntry(top, width=200, placeholder_text="192.168.1.1", font=FONT_MED)
        self.host.pack(side="left", padx=8)

        ctk.CTkLabel(top, text="Comunidade:", font=FONT_MED).pack(side="left")
        self.community = ctk.CTkEntry(top, width=120, placeholder_text="public", font=FONT_MED)
        self.community.pack(side="left", padx=8)
        self.community.insert(0, "public")

        ctk.CTkButton(top, text="▶  SNMP Walk", width=120,
                      fg_color=COLORS["accent"], command=self._walk).pack(side="left", padx=4)
        ctk.CTkButton(top, text="Info Básica", width=100,
                      fg_color=COLORS["sidebar"], command=self._info).pack(side="left", padx=4)

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)

    def _snmp_get(self, oid):
        try:
            from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
            iterator = getCmd(SnmpEngine(),
                              CommunityData(self.community.get()),
                              UdpTransportTarget((self.host.get(), 161)),
                              ContextData(),
                              ObjectType(ObjectIdentity(oid)))
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if errorIndication:
                return None, str(errorIndication)
            elif errorStatus:
                return None, f"{errorStatus.prettyPrint()}"
            else:
                return varBinds[0][1].prettyPrint(), None
        except ImportError:
            return None, "pysnmp não instalado"
        except Exception as e:
            return None, str(e)

    def _snmp_walk(self, oid):
        results = []
        try:
            from pysnmp.hlapi import nextCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
            iterator = nextCmd(SnmpEngine(),
                               CommunityData(self.community.get()),
                               UdpTransportTarget((self.host.get(), 161)),
                               ContextData(),
                               ObjectType(ObjectIdentity(oid)),
                               lexicographicMode=False)
            for errorIndication, errorStatus, errorIndex, varBinds in iterator:
                if errorIndication:
                    break
                if errorStatus:
                    break
                for varBind in varBinds:
                    results.append((varBind[0].prettyPrint(), varBind[1].prettyPrint()))
        except ImportError:
            return None, "pysnmp não instalado"
        except Exception as e:
            return None, str(e)
        return results, None

    def _walk(self):
        threading.Thread(target=self._walk_thread, daemon=True).start()

    def _walk_thread(self):
        host = self.host.get().strip()
        community = self.community.get().strip()
        self.out.clear()
        self.out.header(f"SNMP WALK → {host}  comunidade: {community}")

        # OIDs comuns: 1.3.6.1.2.1.1 (system), 1.3.6.1.2.1.2 (interfaces)
        results, err = self._snmp_walk("1.3.6.1.2.1.1")
        if err:
            self.out.println(f"Erro: {err}", "error")
            return
        if results:
            self.out.println("  ── System ──", "accent")
            for oid, val in results:
                self.out.println(f"  {oid}: {val}", "dim")

        results, err = self._snmp_walk("1.3.6.1.2.1.2.2.1")
        if results:
            self.out.println("\n  ── Interfaces ──", "accent")
            for oid, val in results:
                if "ifDescr" in oid or "ifType" in oid or "ifMtu" in oid or "ifSpeed" in oid:
                    self.out.println(f"  {oid}: {val}", "dim")

    def _info(self):
        threading.Thread(target=self._info_thread, daemon=True).start()

    def _info_thread(self):
        host = self.host.get().strip()
        community = self.community.get().strip()
        self.out.clear()
        self.out.header(f"SNMP INFO → {host}")
        oids = [
            ("1.3.6.1.2.1.1.1.0", "Descrição"),
            ("1.3.6.1.2.1.1.2.0", "OID do sistema"),
            ("1.3.6.1.2.1.1.3.0", "Tempo de atividade"),
            ("1.3.6.1.2.1.1.4.0", "Contato"),
            ("1.3.6.1.2.1.1.5.0", "Nome do host"),
            ("1.3.6.1.2.1.1.6.0", "Localização"),
        ]
        for oid, desc in oids:
            val, err = self._snmp_get(oid)
            if err:
                self.out.println(f"  {desc}: erro ({err})", "error")
            else:
                self.out.println(f"  {desc}: {val}", "success")         

# ================== SSH CLIENT ==================
class SSHClientTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._client = None
        self._build()

    def _build(self):
        # Credenciais
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Host:", font=FONT_MED).pack(side="left")
        self.host = ctk.CTkEntry(top, width=150, placeholder_text="192.168.1.1", font=FONT_MED)
        self.host.pack(side="left", padx=4)

        ctk.CTkLabel(top, text="Porta:", font=FONT_MED).pack(side="left")
        self.port = ctk.CTkEntry(top, width=60, placeholder_text="22", font=FONT_MED)
        self.port.pack(side="left", padx=4)
        self.port.insert(0, "22")

        ctk.CTkLabel(top, text="Usuário:", font=FONT_MED).pack(side="left")
        self.user = ctk.CTkEntry(top, width=100, placeholder_text="root", font=FONT_MED)
        self.user.pack(side="left", padx=4)

        ctk.CTkLabel(top, text="Senha:", font=FONT_MED).pack(side="left")
        self.passwd = ctk.CTkEntry(top, width=100, show="*", font=FONT_MED)
        self.passwd.pack(side="left", padx=4)

        self.btn_connect = ctk.CTkButton(top, text="🔌 Conectar", width=100,
                                          fg_color=COLORS["accent2"], command=self._connect)
        self.btn_connect.pack(side="left", padx=4)
        self.btn_disconnect = ctk.CTkButton(top, text="❌ Desconectar", width=120,
                                             fg_color=COLORS["accent3"], command=self._disconnect,
                                             state="disabled")
        self.btn_disconnect.pack(side="left", padx=4)

        # Comando
        cmd_frame = ctk.CTkFrame(self, fg_color="transparent")
        cmd_frame.pack(fill="x", padx=10, pady=4)
        ctk.CTkLabel(cmd_frame, text="Comando:", font=FONT_MED).pack(side="left")
        self.cmd = ctk.CTkEntry(cmd_frame, width=400, font=FONT_MED)
        self.cmd.pack(side="left", padx=8)
        self.cmd.bind("<Return>", lambda e: self._send_cmd())
        self.btn_send = ctk.CTkButton(cmd_frame, text="▶ Executar", width=100,
                                       fg_color=COLORS["accent"], command=self._send_cmd,
                                       state="disabled")
        self.btn_send.pack(side="left", padx=4)

        self.out = OutputBox(self, height=400)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)

    def _connect(self):
        threading.Thread(target=self._connect_thread, daemon=True).start()

    def _connect_thread(self):
        host = self.host.get().strip()
        port = int(self.port.get() or 22)
        user = self.user.get().strip()
        passwd = self.passwd.get()

        try:
            import paramiko
        except ImportError:
            self.out.println("[ERRO] paramiko não instalado. pip install paramiko", "error")
            return

        self.out.clear()
        self.out.header(f"SSH → {user}@{host}:{port}")
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self._client.connect(host, port=port, username=user, password=passwd, timeout=10)
            self.out.println("  Conectado com sucesso!", "success")
            self.btn_connect.configure(state="disabled")
            self.btn_disconnect.configure(state="normal")
            self.btn_send.configure(state="normal")
        except Exception as e:
            self.out.println(f"  Erro: {e}", "error")
            self._client = None

    def _disconnect(self):
        if self._client:
            self._client.close()
            self._client = None
        self.btn_connect.configure(state="normal")
        self.btn_disconnect.configure(state="disabled")
        self.btn_send.configure(state="disabled")
        self.out.println("\n  Desconectado.", "warning")

    def _send_cmd(self):
        if not self._client:
            return
        cmd = self.cmd.get().strip()
        if not cmd:
            return
        threading.Thread(target=self._exec_thread, args=(cmd,), daemon=True).start()

    def _exec_thread(self, cmd):
        try:
            stdin, stdout, stderr = self._client.exec_command(cmd)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            if out:
                self.out.println(f"\n$ {cmd}", "accent")
                for line in out.splitlines():
                    self.out.println(line, "text")
            if err:
                self.out.println("\n[STDERR]", "error")
                for line in err.splitlines():
                    self.out.println(line, "error")
        except Exception as e:
            self.out.println(f"Erro ao executar: {e}", "error")

# ================== PERFORMANCE GRAPHS ==================
class PerfGraphTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._running = False
        self._data = {"time": [], "rx": [], "tx": []}
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Interface:", font=FONT_MED).pack(side="left")
        ifaces = ["Todas"]
        if PSUTIL_OK:
            ifaces += list(psutil.net_if_stats().keys())
        self.iface = ctk.CTkComboBox(top, values=ifaces, width=160, font=FONT_MED)
        self.iface.set("Todas")
        self.iface.pack(side="left", padx=8)

        ctk.CTkLabel(top, text="Intervalo (s):", font=FONT_MED).pack(side="left")
        self.interval = ctk.CTkEntry(top, width=60, font=FONT_MED)
        self.interval.pack(side="left", padx=8)
        self.interval.insert(0, "1")

        ctk.CTkLabel(top, text="Pontos:", font=FONT_MED).pack(side="left")
        self.max_points = ctk.CTkEntry(top, width=60, font=FONT_MED)
        self.max_points.pack(side="left", padx=8)
        self.max_points.insert(0, "60")

        self.btn_start = ctk.CTkButton(top, text="▶ Iniciar", width=100,
                                        fg_color=COLORS["accent2"], command=self._start)
        self.btn_start.pack(side="left", padx=4)
        self.btn_stop = ctk.CTkButton(top, text="⏹ Parar", width=100,
                                       fg_color=COLORS["accent3"], command=self._stop,
                                       state="disabled")
        self.btn_stop.pack(side="left", padx=4)

        # Área do gráfico
        self.graph_frame = ctk.CTkFrame(self, fg_color=COLORS["card"])
        self.graph_frame.pack(fill="both", expand=True, padx=10, pady=6)

        self.fig = None
        self.ax = None
        self.canvas = None
        self._create_graph()

    def _create_graph(self):
        try:
            import matplotlib
            matplotlib.use("TkAgg")
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            from matplotlib.figure import Figure

            self.fig = Figure(figsize=(8, 4), dpi=100, facecolor=COLORS["card"])
            self.ax = self.fig.add_subplot(111)
            self.ax.set_facecolor(COLORS["bg"])
            self.ax.tick_params(colors=COLORS["text"])
            self.ax.xaxis.label.set_color(COLORS["text"])
            self.ax.yaxis.label.set_color(COLORS["text"])
            self.ax.title.set_color(COLORS["accent"])
            self.ax.grid(True, linestyle='--', alpha=0.6, color=COLORS["border"])

            self.line_rx, = self.ax.plot([], [], label='Download (RX)', color=COLORS["accent"], linewidth=2)
            self.line_tx, = self.ax.plot([], [], label='Upload (TX)', color=COLORS["accent2"], linewidth=2)
            self.ax.legend(loc='upper right', facecolor=COLORS["card"], edgecolor=COLORS["border"])
            self.ax.set_ylabel("Mbps")

            self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_frame)
            self.canvas.get_tk_widget().pack(fill="both", expand=True)
        except ImportError:
            self.out = OutputBox(self, height=420)
            self.out.pack(fill="both", expand=True, padx=10, pady=6)
            self.out.println("[ERRO] matplotlib não instalado.", "error")

    def _start(self):
        if not PSUTIL_OK or self.fig is None:
            return
        self._running = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self._data = {"time": [], "rx": [], "tx": []}
        threading.Thread(target=self._monitor_thread, daemon=True).start()

    def _stop(self):
        self._running = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def _monitor_thread(self):
        interval = float(self.interval.get() or 1)
        max_pts = int(self.max_points.get() or 60)
        prev = psutil.net_io_counters(pernic=True)
        while self._running:
            time.sleep(interval)
            curr = psutil.net_io_counters(pernic=True)
            sel = self.iface.get()

            rx = tx = 0
            for iface, c in curr.items():
                if sel != "Todas" and iface != sel:
                    continue
                p = prev.get(iface)
                if p:
                    rx += (c.bytes_recv - p.bytes_recv) * 8 / interval / 1_000_000  # Mbps
                    tx += (c.bytes_sent - p.bytes_sent) * 8 / interval / 1_000_000
                prev[iface] = c

            # Atualiza dados
            self._data["time"].append(len(self._data["time"]) + 1)
            self._data["rx"].append(rx)
            self._data["tx"].append(tx)
            if len(self._data["time"]) > max_pts:
                self._data["time"] = self._data["time"][-max_pts:]
                self._data["rx"] = self._data["rx"][-max_pts:]
                self._data["tx"] = self._data["tx"][-max_pts:]

            # Atualiza gráfico na thread principal
            self.after(0, self._update_graph)

    def _update_graph(self):
        if not self._running or self.fig is None:
            return
        self.line_rx.set_data(self._data["time"], self._data["rx"])
        self.line_tx.set_data(self._data["time"], self._data["tx"])
        self.ax.relim()
        self.ax.autoscale_view()
        self.ax.set_xlim(left=max(0, len(self._data["time"])-60), right=len(self._data["time"])+1)
        self.canvas.draw()

# ================== HTTP INSPECTOR ==================
class HTTPInspectorTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="URL:", font=FONT_MED).pack(side="left")
        self.url = ctk.CTkEntry(top, width=400, placeholder_text="https://example.com", font=FONT_MED)
        self.url.pack(side="left", padx=8)
        self.url.insert(0, "https://example.com")

        ctk.CTkButton(top, text="🔍 Inspecionar", width=120,
                      fg_color=COLORS["accent"], command=self._run).pack(side="left", padx=4)
        ctk.CTkButton(top, text="🔒 SSL/TLS", width=100,
                      fg_color=COLORS["sidebar"], command=self._ssl).pack(side="left", padx=4)

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)

    def _run(self):
        threading.Thread(target=self._inspect_thread, daemon=True).start()

    def _inspect_thread(self):
        url = self.url.get().strip()
        self.out.clear()
        self.out.header(f"HTTP INSPECTOR → {url}")

        if not REQUESTS_OK:
            self.out.println("[ERRO] requests não instalado.", "error")
            return

        try:
            # Primeiro, um HEAD para ver métodos suportados?
            r = requests.head(url, timeout=10, allow_redirects=True, verify=False)
            self.out.println(f"  URL final: {r.url}", "accent")
            self.out.println(f"  Status: {r.status_code} {r.reason}", "success" if r.status_code < 400 else "error")
            self.out.println(f"  Server: {r.headers.get('Server', '?')}")
            self.out.println(f"  Content-Type: {r.headers.get('Content-Type', '?')}")

            # Segurança
            self.out.println("\n  ── Segurança ──", "accent")
            hsts = r.headers.get('Strict-Transport-Security')
            self.out.println(f"  HSTS: {hsts or 'Não configurado'}", "success" if hsts else "warning")
            csp = r.headers.get('Content-Security-Policy')
            self.out.println(f"  CSP: {csp or 'Não configurado'}", "success" if csp else "warning")
            xframe = r.headers.get('X-Frame-Options')
            self.out.println(f"  X-Frame-Options: {xframe or 'Não configurado'}", "success" if xframe else "warning")

            # Métodos HTTP permitidos (OPTIONS)
            try:
                opts = requests.options(url, timeout=5, verify=False)
                allow = opts.headers.get('Allow', '')
                self.out.println(f"\n  Métodos permitidos: {allow}", "accent")
            except:
                pass

            # Headers completos
            self.out.println("\n  ── Headers Completos ──", "accent")
            for k, v in r.headers.items():
                self.out.println(f"  {k}: {v}", "dim")

        except Exception as e:
            self.out.println(f"  Erro: {e}", "error")

    def _ssl(self):
        threading.Thread(target=self._ssl_thread, daemon=True).start()

    def _ssl_thread(self):
        import ssl
        url = self.url.get().strip()
        host = re.sub(r"https?://", "", url).split("/")[0].split(":")[0]
        self.out.clear()
        self.out.header(f"SSL/TLS → {host}")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    self.out.println(f"  Protocolo: {ssock.version()}", "success")
                    self.out.println(f"  Cipher: {ssock.cipher()[0]}")
                    self.out.println(f"  Bits: {ssock.cipher()[2]}")
                    # Informações do certificado
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    self.out.println(f"\n  Emitido por: {issuer.get('organizationName', '?')}")
                    self.out.println(f"  Válido para: {subject.get('commonName', '?')}")
                    self.out.println(f"  Válido até: {cert['notAfter']}", "warning")
                    # SANs
                    sans = [v for _, v in cert.get('subjectAltName', [])]
                    if sans:
                        self.out.println("\n  SANs:", "accent")
                        for name in sans[:10]:
                            self.out.println(f"    {name}", "dim")
        except Exception as e:
            self.out.println(f"  Erro: {e}", "error")

# ================== DNS ENUMERATION ==================
class DNSEnumTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        # used to interrupt the brute‑force thread; initialized here so the
        # attribute always exists (avoids AttributeError seen in log)
        self._stop_flag = False
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Domínio:", font=FONT_MED).pack(side="left")
        self.domain = ctk.CTkEntry(top, width=200, placeholder_text="example.com", font=FONT_MED)
        self.domain.pack(side="left", padx=8)
        self.domain.insert(0, "example.com")

        ctk.CTkButton(top, text="🔎 Zone Transfer", width=140,
                      fg_color=COLORS["accent"], command=self._axfr).pack(side="left", padx=4)
        ctk.CTkButton(top, text="📋 Brute Subdomínios", width=160,
                      fg_color=COLORS["accent2"], command=self._brute).pack(side="left", padx=4)
        ctk.CTkButton(top, text="✖ Parar", width=90,
                      fg_color=COLORS["accent3"], command=self._stop).pack(side="left", padx=4)
        ctk.CTkButton(top, text="↩️ Reverse PTR", width=120,
                      fg_color=COLORS["sidebar"], command=self._reverse).pack(side="left", padx=4)

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)

        # Wordlist para brute force
        self.wordlist = ctk.CTkEntry(self, placeholder_text="Caminho da wordlist (opcional)", font=FONT_SMALL)
        self.wordlist.pack(fill="x", padx=10, pady=2)

    def _axfr(self):
        threading.Thread(target=self._axfr_thread, daemon=True).start()

    def _axfr_thread(self):
        domain = self.domain.get().strip()
        self.out.clear()
        self.out.header(f"ZONE TRANSFER → {domain}")

        if not DNS_OK:
            self.out.println("[ERRO] dnspython não instalado.", "error")
            return

        try:
            # Obtém nameservers do domínio
            ns_answers = dns.resolver.resolve(domain, 'NS')
            self.out.println("  Nameservers encontrados:", "accent")
            for ns in ns_answers:
                ns_str = str(ns.target)
                self.out.println(f"    {ns_str}")
                # Tenta AXFR
                try:
                    axfr = dns.query.xfr(ns_str, domain, timeout=10)
                    zone = dns.zone.from_xfr(axfr)
                    if zone:
                        self.out.println(f"\n  Zone Transfer bem-sucedida de {ns_str}:", "success")
                        for name, node in zone.nodes.items():
                            rdatasets = node.rdatasets
                            for rdataset in rdatasets:
                                self.out.println(f"    {name} {rdataset}", "dim")
                except Exception as e:
                    self.out.println(f"    Falha AXFR em {ns_str}: {e}", "error")
        except Exception as e:
            self.out.println(f"Erro: {e}", "error")

    def _brute(self):
        # reset flag each time we start the operation
        self._stop_flag = False
        threading.Thread(target=self._brute_thread, daemon=True).start()

    def _brute_thread(self):
        domain = self.domain.get().strip()
        wordlist_path = self.wordlist.get().strip()
        self.out.clear()
        self.out.header(f"BRUTE FORCE SUBDOMÍNIOS → {domain}")

        # Wordlist padrão (alguns nomes comuns)
        subdomains = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
                      "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
                      "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
                      "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
                      "docs", "resources", "intranet", "portal", "demo", "beta", "shop", "secure"]
        # note: _stop_flag checked above; loop will exit cleanly when user clicks
        # the new "Parar" button or the operation completes
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path) as f:
                subdomains = [line.strip() for line in f if line.strip()]

        found = []
        for sub in subdomains:
            if self._stop_flag:
                break
            fqdn = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(fqdn, 'A')
                if answers:
                    ips = ", ".join(str(r) for r in answers)
                    self.out.println(f"  ✓ {fqdn} → {ips}", "success")
                    found.append(fqdn)
            except:
                pass
        self.out.println(f"\n  Total encontrados: {len(found)}", "accent")

    def _stop(self):
        # signal the brute thread to halt
        self._stop_flag = True

    def _reverse(self):
        threading.Thread(target=self._reverse_thread, daemon=True).start()

    def _reverse_thread(self):
        ip_range = self.domain.get().strip()  # Pode ser um IP ou CIDR
        self.out.clear()
        self.out.header(f"REVERSE PTR → {ip_range}")

        if not DNS_OK:
            self.out.println("[ERRO] dnspython não instalado.", "error")
            return

        try:
            if '/' in ip_range:
                network = ipaddress.ip_network(ip_range, strict=False)
                hosts = list(network.hosts())[:256]  # limit
            else:
                hosts = [ipaddress.ip_address(ip_range)]

            for ip in hosts:
                try:
                    rev = dns.reversename.from_address(str(ip))
                    answers = dns.resolver.resolve(rev, 'PTR')
                    for ans in answers:
                        self.out.println(f"  {ip} → {ans}", "success")
                except:
                    pass
        except Exception as e:
            self.out.println(f"Erro: {e}", "error")

# ================== MTR (My Traceroute) ==================
class MTRTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._running = False
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Destino:", font=FONT_MED).pack(side="left")
        self.host = ctk.CTkEntry(top, width=200, placeholder_text="8.8.8.8", font=FONT_MED)
        self.host.pack(side="left", padx=8)
        self.host.insert(0, "8.8.8.8")

        self.btn_start = ctk.CTkButton(top, text="▶ Iniciar MTR", width=120,
                                        fg_color=COLORS["accent2"], command=self._start)
        self.btn_start.pack(side="left", padx=4)
        self.btn_stop = ctk.CTkButton(top, text="⏹ Parar", width=100,
                                       fg_color=COLORS["accent3"], command=self._stop,
                                       state="disabled")
        self.btn_stop.pack(side="left", padx=4)

        self.out = OutputBox(self, height=420)
        self.out.pack(fill="both", expand=True, padx=10, pady=6)

        self._stats = {}  # hop -> (min, max, avg, loss, last)

    def _start(self):
        self._running = True
        self._stats.clear()
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.out.clear()
        self.out.header(f"MTR → {self.host.get()}")
        threading.Thread(target=self._mtr_thread, daemon=True).start()

    def _stop(self):
        self._running = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def _mtr_thread(self):
        dest = self.host.get().strip()
        max_hops = 30

        # Descobre o caminho primeiro
        hops_map = {}  # ttl -> ip
        for ttl in range(1, max_hops+1):
            if not self._running:
                return
            # Envia pacote com TTL específico (ICMP ou UDP)
            # Vamos usar ping com TTL (no Linux, ping -t, no Windows -i)
            # Alternativa mais simples: usar traceroute uma vez para mapear hops
            # Mas para manter a simplicidade, faremos um traceroute inicial
            break

        # Fallback: usar comando system mtr se disponível
        try:
            if sys.platform != "win32":
                cmd = ["mtr", "--report-wide", "--no-dns", "--report-cycles", "5", dest]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for line in proc.stdout:
                    if not self._running:
                        proc.terminate()
                        break
                    self.out.println(line.rstrip())
                return
        except:
            pass

        # Simulação simples: ping progressivo
        for ttl in range(1, max_hops+1):
            if not self._running:
                break
            # Ping com TTL específico (no Linux: ping -t ttl dest)
            # No Windows: ping -i ttl
            if sys.platform == "win32":
                cmd = ["ping", "-n", "1", "-i", str(ttl), dest]
            else:
                cmd = ["ping", "-c", "1", "-t", str(ttl), dest]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                # Extrair IP do hop e tempo
                # Isso é bem complexo de parsear, então simplificamos:
                self.out.println(f"  Hop {ttl}: ...", "dim")
            except:
                self.out.println(f"  Hop {ttl}: *", "error")
            time.sleep(0.5)

        self.out.println("\nMTR finalizado.", "accent")

# ================== NETWORK CONFIG MANAGER ==================
class NetConfigTab(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self._build()

    def _build(self):
        notebook = ctk.CTkTabview(self, fg_color="transparent")
        notebook.pack(fill="both", expand=True, padx=10, pady=6)

        # Aba Hosts File
        hosts_tab = notebook.add("Hosts File")
        self._build_hosts(hosts_tab)

        # Aba DNS Cache
        dns_tab = notebook.add("DNS Cache")
        self._build_dns(dns_tab)

        # Aba Interfaces (config rápida)
        iface_tab = notebook.add("Configurar IP")
        self._build_iface(iface_tab)

    def _build_hosts(self, parent):
        top = ctk.CTkFrame(parent, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(top, text="Gerenciar arquivo hosts", font=FONT_BOLD).pack(anchor="w")
        self.hosts_text = OutputBox(parent, height=250)
        self.hosts_text.pack(fill="both", expand=True, padx=10, pady=6)

        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=4)

        ctk.CTkButton(btn_frame, text="📂 Carregar hosts", command=self._load_hosts,
                      fg_color=COLORS["accent"]).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="💾 Salvar hosts", command=self._save_hosts,
                      fg_color=COLORS["accent2"]).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="🔄 Flush DNS", command=self._flush_dns,
                      fg_color=COLORS["warning"]).pack(side="left", padx=4)

        self._load_hosts()

    def _load_hosts(self):
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if sys.platform == "win32" else "/etc/hosts"
        try:
            with open(hosts_path, "r") as f:
                content = f.read()
            self.hosts_text.clear()
            self.hosts_text.println(content)
        except Exception as e:
            self.hosts_text.clear()
            self.hosts_text.println(f"Erro ao ler hosts: {e}", "error")

    def _save_hosts(self):
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if sys.platform == "win32" else "/etc/hosts"
        try:
            content = self.hosts_text.get("1.0", "end-1c")
            with open(hosts_path, "w") as f:
                f.write(content)
            messagebox.showinfo("Hosts", "Arquivo hosts salvo com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível salvar: {e}")

    def _flush_dns(self):
        try:
            if sys.platform == "win32":
                subprocess.run(["ipconfig", "/flushdns"], check=True, capture_output=True)
            else:
                subprocess.run(["systemd-resolve", "--flush-caches"], check=True, capture_output=True)
            messagebox.showinfo("DNS", "Cache DNS limpo com sucesso!")
        except:
            messagebox.showerror("Erro", "Falha ao limpar cache DNS")

    def _build_dns(self, parent):
        ctk.CTkLabel(parent, text="Visualizar cache DNS (requer privilégios)").pack(pady=10)
        self.dns_out = OutputBox(parent, height=300)
        self.dns_out.pack(fill="both", expand=True, padx=10, pady=6)
        ctk.CTkButton(parent, text="Mostrar cache DNS", command=self._show_dns_cache).pack(pady=4)

    def _show_dns_cache(self):
        self.dns_out.clear()
        try:
            if sys.platform == "win32":
                result = subprocess.run(["ipconfig", "/displaydns"], capture_output=True, text=True)
                self.dns_out.println(result.stdout)
            else:
                self.dns_out.println("Comando não implementado para Linux/Mac. Use 'sudo killall -USR1 systemd-resolved' e veja journalctl.")
        except Exception as e:
            self.dns_out.println(f"Erro: {e}", "error")

    def _build_iface(self, parent):
        ctk.CTkLabel(parent, text="Configuração rápida de IP (requer admin)").pack(pady=10)

        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(pady=4)

        ctk.CTkLabel(frame, text="Interface:").grid(row=0, column=0, padx=5, pady=2)
        self.iface_combo = ctk.CTkComboBox(frame, values=["eth0", "wlan0"])
        self.iface_combo.grid(row=0, column=1, padx=5, pady=2)

        ctk.CTkLabel(frame, text="IP:").grid(row=1, column=0, padx=5, pady=2)
        self.ip_entry = ctk.CTkEntry(frame, width=150)
        self.ip_entry.grid(row=1, column=1, padx=5, pady=2)

        ctk.CTkLabel(frame, text="Máscara:").grid(row=2, column=0, padx=5, pady=2)
        self.netmask_entry = ctk.CTkEntry(frame, width=150, placeholder_text="255.255.255.0")
        self.netmask_entry.grid(row=2, column=1, padx=5, pady=2)

        ctk.CTkLabel(frame, text="Gateway:").grid(row=3, column=0, padx=5, pady=2)
        self.gw_entry = ctk.CTkEntry(frame, width=150)
        self.gw_entry.grid(row=3, column=1, padx=5, pady=2)

        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="Aplicar (Linux)", command=self._apply_linux,
                      fg_color=COLORS["accent"]).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="Aplicar (Windows)", command=self._apply_windows,
                      fg_color=COLORS["accent2"]).pack(side="left", padx=4)

    def _apply_linux(self):
        iface = self.iface_combo.get()
        ip = self.ip_entry.get()
        netmask = self.netmask_entry.get() or "255.255.255.0"
        gw = self.gw_entry.get()
        try:
            # ifconfig ou ip addr
            subprocess.run(["sudo", "ip", "addr", "add", f"{ip}/{self._mask_to_cidr(netmask)}", "dev", iface], check=True)
            if gw:
                subprocess.run(["sudo", "ip", "route", "add", "default", "via", gw], check=True)
            messagebox.showinfo("Sucesso", "Configuração aplicada.")
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def _apply_windows(self):
        iface = self.iface_combo.get()
        ip = self.ip_entry.get()
        netmask = self.netmask_entry.get()
        gw = self.gw_entry.get()
        try:
            # netsh
            cmd = ["netsh", "interface", "ip", "set", "address", f"name={iface}",
                   f"source=static", f"addr={ip}", f"mask={netmask}"]
            if gw:
                cmd.append(f"gateway={gw}")
            subprocess.run(cmd, check=True, shell=True)
            messagebox.showinfo("Sucesso", "Configuração aplicada.")
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def _mask_to_cidr(self, mask):
        return sum(bin(int(x)).count('1') for x in mask.split('.'))

# ═══════════════════════════════════════════════════════════════════
#                       JANELA PRINCIPAL
# ═══════════════════════════════════════════════════════════════════
class NetworkDashboard(ctk.CTk):
    TOOLS = [
        ("🏓 Ping",          PingTab),
        ("🔀 Traceroute",    TracerouteTab),
        ("🔍 Port Scanner",  PortScannerTab),
        ("🌐 DNS Lookup",    DNSTab),
        ("📋 Whois",         WhoisTab),
        ("🖧 Interfaces",    InterfacesTab),
        ("📊 Bandwidth",     BandwidthTab),
        ("🔒 HTTP/HTTPS",    HTTPTab),
        ("🔢 Subnet Calc",   SubnetTab),
        ("🌍 GeoIP",         GeoIPTab),
        ("📡 Wake-on-LAN",   WakeOnLANTab),
        ("⚡ Speed Test",    SpeedTestTab),
        ("📈 Netstat",       NetstatTab),
        # ---------- NOVAS FERRAMENTAS ----------
        ("🔎 Network Discovery", NetworkDiscoveryTab),
        ("📦 Packet Sniffer",    PacketSnifferTab),
        ("📡 SNMP Scanner",      SNMPTab),
        ("🔑 SSH Client",        SSHClientTab),
        ("📊 Performance Graphs",PerfGraphTab),
        ("🌐 HTTP Inspector",    HTTPInspectorTab),
        ("🔍 DNS Enumeration",   DNSEnumTab),
        ("📱 MTR",               MTRTab),
        ("⚙️  Network Config",    NetConfigTab),
    ]

    def __init__(self):
        super().__init__()
        self.title("3DV5 REDES TOOLS")
        self.geometry("1280x760")
        self.configure(fg_color=COLORS["bg"])
        self.minsize(900, 600)

        self._tabs: dict[str, ctk.CTkFrame] = {}
        self._active_btn = None
        self._build()
        self._select(0)

    def _build(self):
        # ── Top bar ──
        topbar = ctk.CTkFrame(self, fg_color=COLORS["sidebar"],
                              height=48, corner_radius=0)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        ctk.CTkLabel(
            topbar, text="3DV5 REDES TOOLS",
            font=("Segoe UI", 14, "bold"),
            text_color=COLORS["accent"]
        ).pack(side="left", padx=10)

        # Status bar (deps)
        deps = []
        if PSUTIL_OK:  deps.append("psutil ✓")
        else:          deps.append("psutil ✗")
        if DNS_OK:     deps.append("dnspython ✓")
        else:          deps.append("dnspython ✗")
        if REQUESTS_OK: deps.append("requests ✓")
        else:            deps.append("requests ✗")

        ctk.CTkLabel(
            topbar,
            text="  |  " + "   ".join(deps),
            font=FONT_SMALL, text_color=COLORS["text_dim"]
        ).pack(side="left")

        ctk.CTkLabel(
            topbar,
            text=f"Hostname: {socket.gethostname()}    ",
            font=FONT_SMALL, text_color=COLORS["text_dim"]
        ).pack(side="right")

        # ── Main layout ──
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True)

        # ── Sidebar ──
        # wrap the scrollable frame inside a fixed-width container so the
        # scrollbar doesn't change the overall width of the sidebar
        sidebar_container = ctk.CTkFrame(main, fg_color=COLORS["sidebar"],
                                         width=190, corner_radius=0)
        sidebar_container.pack(side="left", fill="y")
        sidebar_container.pack_propagate(False)

        ctk.CTkLabel(sidebar_container, text=" FERRAMENTAS",
                     font=("Segoe UI", 10, "bold"),
                     text_color=COLORS["text_dim"]).pack(
            anchor="w", padx=12, pady=(14, 4))

        # use a scrollable frame for the list of buttons so additional tools
        # are still reachable when the window is not tall enough
        sidebar = ctk.CTkScrollableFrame(sidebar_container,
                                         fg_color="transparent",
                                         border_width=0)
        sidebar.pack(fill="both", expand=True, padx=0, pady=0)

        self._btns = []
        for i, (name, _cls) in enumerate(self.TOOLS):
            btn = ctk.CTkButton(
                sidebar, text=name,
                font=FONT_MED, anchor="w",
                height=36, corner_radius=6,
                fg_color="transparent",
                hover_color=COLORS["card"],
                text_color=COLORS["text"],
                command=lambda idx=i: self._select(idx)
            )
            btn.pack(fill="x", padx=8, pady=2)
            self._btns.append(btn)

        # ── Content ──
        self._content = ctk.CTkFrame(main, fg_color=COLORS["bg"],
                                     corner_radius=0)
        self._content.pack(side="left", fill="both", expand=True)

    def _select(self, idx: int):
        name, cls = self.TOOLS[idx]

        # Hide all
        for tab in self._tabs.values():
            tab.pack_forget()

        # Reset buttons
        for b in self._btns:
            b.configure(fg_color="transparent",
                        text_color=COLORS["text"])
        self._btns[idx].configure(
            fg_color=COLORS["card"],
            text_color=COLORS["accent"])

        # Create or show
        if name not in self._tabs:
            frame = cls(self._content)
            self._tabs[name] = frame

        self._tabs[name].pack(fill="both", expand=True)


# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = NetworkDashboard()
    app.mainloop()