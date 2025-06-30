#!/usr/bin/env python3
"""
NeonCrack - Cyberpunk WPA/WPA2 Handshake Cracker GUI
Author: Niko DeRuise

USAGE:
sudo python3 neoncrack.py

REQUIREMENTS:
- aircrack-ng
- tkinter (Python 3.x)
"""

import subprocess
import threading
from tkinter import *
from tkinter import filedialog, scrolledtext, messagebox

# === GUI Setup ===
root = Tk()
root.title("🧬 NeonCrack - Cyberpunk Handshake Cracker")
root.geometry("800x500")
root.configure(bg="#0f0f23")  # Deep cyberpunk black/blue

# === Variables ===
pcap_file = StringVar()
wordlist_file = StringVar()

# === Functions ===
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
        messagebox.showerror("⛔ Missing Input", "Please select both a pcap file and a wordlist.")
        return
    
    output_box.delete(1.0, END)
    crack_button.config(state=DISABLED)

    def crack_thread():
        try:
            cmd = ["aircrack-ng", "-w", wordlist_file.get(), pcap_file.get()]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            for line in process.stdout:
                output_box.insert(END, line)
                output_box.see(END)

            process.wait()
            crack_button.config(state=NORMAL)
        except Exception as e:
            output_box.insert(END, f"\n⚠️ Error: {e}\n")
            crack_button.config(state=NORMAL)

    threading.Thread(target=crack_thread).start()

# === Cyberpunk GUI Styling ===

style_font = ("Courier New", 12, "bold")
neon_color = "#39ff14"
accent_color = "#ff0080"

def styled_label(text):
    return Label(root, text=text, fg=neon_color, bg="#0f0f23", font=style_font)

def styled_button(text, command):
    return Button(root, text=text, command=command, bg=accent_color, fg="white", activebackground="#ff33aa", activeforeground="black", font=style_font, relief=RAISED, bd=2)

# === Layout ===

styled_label("📂 PCAP Handshake File:").pack(pady=(10, 0))
Entry(root, textvariable=pcap_file, width=80, font=("Courier", 10), bg="#1a1a1a", fg="lime", insertbackground="white").pack()
styled_button("Select Handshake", select_pcap).pack(pady=5)

styled_label("🧾 Wordlist File:").pack(pady=(10, 0))
Entry(root, textvariable=wordlist_file, width=80, font=("Courier", 10), bg="#1a1a1a", fg="lime", insertbackground="white").pack()
styled_button("Select Wordlist", select_wordlist).pack(pady=5)

crack_button = styled_button("💥 Start Cracking", run_crack)
crack_button.pack(pady=20)

output_box = scrolledtext.ScrolledText(root, wrap=WORD, width=95, height=12, font=("Courier", 10), bg="black", fg=neon_color, insertbackground="white")
output_box.pack(padx=10, pady=10)

# === Start GUI ===
root.mainloop()