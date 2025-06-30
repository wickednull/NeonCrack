#!/usr/bin/env python3
"""
NeonCrack v1.2 - Cyberpunk WPA Handshake Cracking Suite
Author: Niko DeRuise

USAGE:
sudo python3 neoncrack.py

DEPENDENCIES:
- aircrack-ng
- cap2hccapx (for Cleaner tab)
- python3-tk
- hashid (optional for Hash ID tab)
"""

import subprocess
import threading
import time
import re
from tkinter import *
from tkinter import ttk, filedialog, messagebox, scrolledtext

# === Initialize Window ===
root = Tk()
root.title("🧬 NeonCrack v2 - Cyberpunk Cracking Suite")
root.geometry("1000x600")
root.configure(bg="#0f0f23")

# === Global Variables ===
pcap_file = StringVar()
wordlist_file = StringVar()
hash_input = StringVar()
converted_file = StringVar()
crack_result = ""

# === Style Definitions ===
neon = "#39ff14"
accent = "#ff0080"
bgcolor = "#0f0f23"
font_main = ("Courier New", 11, "bold")

style = ttk.Style()
style.theme_use("clam")
style.configure("TNotebook", background=bgcolor, borderwidth=0)
style.configure("TNotebook.Tab", background=bgcolor, foreground=neon, padding=10, font=font_main)
style.map("TNotebook.Tab", background=[("selected", accent)], foreground=[("selected", "white")])

# === Sidebar Layout ===
main_frame = Frame(root, bg=bgcolor)
main_frame.pack(fill=BOTH, expand=True)

notebook = ttk.Notebook(main_frame)
notebook.pack(side=LEFT, fill=Y)

content_frame = Frame(main_frame, bg=bgcolor)
content_frame.pack(side=LEFT, fill=BOTH, expand=True)

tabs = {}

def add_tab(name):
    tab = Frame(content_frame, bg=bgcolor)
    tabs[name] = tab
    notebook.add(tab, text=name)

# === Tabs ===
add_tab("🧨 Crack")
add_tab("🔎 Hash ID")
add_tab("🧹 Cleaner")
add_tab("📊 Stats")

# === CRACK TAB ===
def crack_gui():
    frame = tabs["🧨 Crack"]

    Label(frame, text="Handshake File (.cap/.pcap):", bg=bgcolor, fg=neon, font=font_main).pack(pady=(10,0))
    Entry(frame, textvariable=pcap_file, width=80, bg="#1a1a1a", fg=neon, insertbackground="white").pack()
    Button(frame, text="Select Handshake", command=select_pcap, bg=accent, fg="white", font=font_main).pack(pady=5)

    Label(frame, text="Wordlist File:", bg=bgcolor, fg=neon, font=font_main).pack(pady=(10,0))
    Entry(frame, textvariable=wordlist_file, width=80, bg="#1a1a1a", fg=neon, insertbackground="white").pack()
    Button(frame, text="Select Wordlist", command=select_wordlist, bg=accent, fg="white", font=font_main).pack(pady=5)

    Button(frame, text="💥 Start Cracking", command=run_crack, bg=accent, fg="white", font=font_main).pack(pady=10)

    global crack_output
    crack_output = scrolledtext.ScrolledText(frame, width=100, height=15, bg="black", fg=neon, font=("Courier", 10))
    crack_output.pack(padx=10, pady=10)

def select_pcap():
    file = filedialog.askopenfilename(filetypes=[("PCAP/Handshake Files", "*.cap *.pcap")])
    if file:
        pcap_file.set(file)

def select_wordlist():
    file = filedialog.askopenfilename(filetypes=[("Wordlist Files", "*.txt")])
    if file:
        wordlist_file.set(file)

def run_crack():
    if not pcap_file.get() or not wordlist_file.get():
        messagebox.showerror("Missing input", "Please select both a handshake and a wordlist.")
        return

    crack_output.delete(1.0, END)

    def thread_crack():
        global crack_result
        crack_output.insert(END, "[*] Launching aircrack-ng...\n")
        start = time.time()
        cmd = ["aircrack-ng", "-w", wordlist_file.get(), pcap_file.get()]
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                crack_output.insert(END, line)
                crack_output.see(END)
                if "KEY FOUND!" in line:
                    crack_result = line.strip()
            process.wait()
            duration = time.time() - start
            crack_output.insert(END, f"\n[*] Done in {duration:.2f} seconds\n")
        except Exception as e:
            crack_output.insert(END, f"[!] Error: {e}\n")

    threading.Thread(target=thread_crack).start()

crack_gui()

# === HASH ID TAB ===
def hashid_gui():
    frame = tabs["🔎 Hash ID"]

    Label(frame, text="Enter a hash below:", bg=bgcolor, fg=neon, font=font_main).pack(pady=(15, 5))
    hash_entry = Entry(frame, textvariable=hash_input, width=90, bg="#1a1a1a", fg="lime", insertbackground="white", font=("Courier", 10))
    hash_entry.pack()

    Button(frame, text="🔍 Identify Hash Type", command=run_hashid, bg=accent, fg="white", font=font_main).pack(pady=10)

    global hash_output
    hash_output = scrolledtext.ScrolledText(frame, width=100, height=15, bg="black", fg=neon, font=("Courier", 10))
    hash_output.pack(padx=10, pady=10)

def run_hashid():
    hash_output.delete(1.0, END)
    h = hash_input.get().strip()

    if not h:
        hash_output.insert(END, "[!] No hash provided.\n")
        return

    # Simple pattern logic
    patterns = {
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA1": r"^[a-fA-F0-9]{40}$",
        "SHA256": r"^[a-fA-F0-9]{64}$",
        "SHA512": r"^[a-fA-F0-9]{128}$",
        "WPA/WPA2 PSK": r"^[a-fA-F0-9]{64}$",
        "NTLM": r"^[a-fA-F0-9]{32}$",
        "bcrypt": r"^\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$",
    }

    matches = []
    for name, pattern in patterns.items():
        if re.match(pattern, h):
            matches.append(name)

    if matches:
        hash_output.insert(END, "[*] Possible Hash Types:\n")
        for m in matches:
            hash_output.insert(END, f" - {m}\n")
    else:
        hash_output.insert(END, "[!] Could not identify hash type with known patterns.\n")

    try:
        proc = subprocess.run(["hashid", h], capture_output=True, text=True)
        if proc.returncode == 0:
            hash_output.insert(END, "\n[+] hashid CLI Output:\n")
            hash_output.insert(END, proc.stdout)
    except FileNotFoundError:
        hash_output.insert(END, "\n[!] hashid CLI not found. Install with:\n    pip install hashid\n")

hashid_gui()

# === CLEANER TAB ===
def cleaner_gui():
    frame = tabs["🧹 Cleaner"]

    Label(frame, text="Convert .cap to .hccapx (for Hashcat)", bg=bgcolor, fg=neon, font=font_main).pack(pady=(15, 5))
    Button(frame, text="📂 Select Capture File", command=select_clean_target, bg=accent, fg="white", font=font_main).pack(pady=5)
    Entry(frame, textvariable=pcap_file, width=90, bg="#1a1a1a", fg=neon, font=("Courier", 10), insertbackground="white").pack()
    Button(frame, text="⚙️ Clean & Convert", command=run_clean_convert, bg=accent, fg="white", font=font_main).pack(pady=10)

    global clean_output
    clean_output = scrolledtext.ScrolledText(frame, width=100, height=15, bg="black", fg=neon, font=("Courier", 10))
    clean_output.pack(padx=10, pady=10)

def select_clean_target():
    file = filedialog.askopenfilename(filetypes=[("Capture Files", "*.cap *.pcap")])
    if file:
        pcap_file.set(file)

def run_clean_convert():
    clean_output.delete(1.0, END)
    cap = pcap_file.get().strip()

    if not cap:
        clean_output.insert(END, "[!] No capture file selected.\n")
        return

    hccapx_path = cap.rsplit(".", 1)[0] + ".hccapx"
    converted_file.set(hccapx_path)

    try:
        clean_output.insert(END, f"[*] Converting {cap} to {hccapx_path}...\n")
        cmd = ["cap2hccapx", cap, hccapx_path]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            clean_output.insert(END, f"[+] Success! Saved as:\n    {hccapx_path}\n")
        else:
            clean_output.insert(END, f"[!] Conversion failed:\n{result.stderr}\n")
    except FileNotFoundError:
        clean_output.insert(END, "[!] cap2hccapx not found. Install with: sudo apt install hashcat-utils\n")

cleaner_gui()

# === STATS TAB ===
def stats_gui():
    frame = tabs["📊 Stats"]

    Label(frame, text="📊 Cracking Results", bg=bgcolor, fg=neon, font=font_main).pack(pady=(15, 5))

    global stats_output
    stats_output = scrolledtext.ScrolledText(frame, width=100, height=15, bg="black", fg=neon, font=("Courier", 10))
    stats_output.pack(padx=10, pady=10)

    Button(frame, text="📥 Load Last Crack Result", command=load_last_crack, bg=accent, fg="white", font=font_main).pack(pady=5)
    Button(frame, text="💾 Save to cracked_results.txt", command=save_result, bg=accent, fg="white", font=font_main).pack(pady=5)

def load_last_crack():
    stats_output.delete(1.0, END)
    if crack_result:
        stats_output.insert(END, f"{crack_result}\n")
    else:
        stats_output.insert(END, "[!] No result found. Run a crack first.\n")

def save_result():
    if not crack_result:
        messagebox.showinfo("Nothing to Save", "No cracked password result to save.")
        return

    try:
        with open("cracked_results.txt", "a") as f:
            f.write(f"{crack_result}\n")
        messagebox.showinfo("Saved", "Result saved to cracked_results.txt")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save: {e}")

stats_gui()

# === Start GUI ===
root.mainloop()