![image](https://github.com/user-attachments/assets/98c1370a-47e6-4927-8484-9343c74c2ea5)

# 🧬 NeonCrack v1.4 — Cyberpunk WPA/PMKID Cracking Toolkit

**NeonCrack** is a visually immersive, cyberpunk-themed wireless cracking suite built for ethical hackers, red teamers, and cybersecurity enthusiasts. It brings together powerful open-source tools like `aircrack-ng` and `hcxtools` under a unified, user-friendly Python GUI — all themed in high-voltage neon.

---

## ⚡ Features

### 📡 Wireless Capture
- Scan for nearby Wi-Fi networks
- Select a target AP (BSSID, channel, ESSID)
- Capture PMKID handshakes via `airodump-ng`
- Save `.pcap` files to `neoncrack_captures/`

### 🧨 WPA Handshake Cracker
- Load `.cap` or `.pcap` handshake files
- Use any custom wordlist (e.g. `rockyou.txt`)
- Crack with `aircrack-ng` and view results live

### 🔎 Hash Identifier
- Detect hash types (MD5, SHA1, SHA256, WPA, bcrypt, etc.)
- Uses regex and optional CLI tool `hashid`

### 🧹 Capture Cleaner
- Convert `.pcapng` or `.cap` to `.hccapx` using `hcxpcapngtool`
- Prepare for external tools like `hashcat`

### 📊 Stats & Logging
- View cracked password stats
- Save successful keys to `cracked_results.txt`

---


### 🔧 Dependencies

```bash
sudo apt update && sudo apt install aircrack-ng hcxtools python3-tk xterm
pip3 install hashid  # optional
```

🧠 Running NeonCrack

🔸 Standard Linux Systems:
```bash
sudo python3 neoncrackV1.4.py
```
🔸 On NetHunter Pro (e.g. PinePhone):
1.	Boot into Kali NetHunter Pro
2.	Ensure monitor mode works

 Test your WiFi adapter:
```bash
iwconfig
sudo airmon-ng start wlan1  # replace with correct interface
```

3.	Give X11 Permissions (Important)
On NetHunter Pro with GUI, run this if you get display issues:
```bash
xhost +SI:localuser:root
```
4.	Run the GUI Script:
   ```bash
sudo python3 neoncrackV1.4.py
```
⚠️ NetHunter Pro Special Notes
	•	For Alfa USB adapters (e.g., AC600), ensure drivers are working
	•	You may need a powered OTG hub for full performance
	•	Test monitor mode with:
 ```bash
sudo airmon-ng start wlan1
sudo airodump-ng wlan1mon
```
   
If NeonCrack shows no networks, verify:
	•	Monitor mode is active
	•	You selected the correct interface
	•	You gave X11 permission (xhost +)






⸻

Developed by Null_Lyfe_tcl

🧾 Credits

NeonCrack was built on the shoulders of open-source giants:
	•	Aircrack-ng
	•	hcxtools
	•	Tkinter
	•	hashid
	•	SecLists

⚠️ Disclaimer

NeonCrack is intended solely for legal security testing and educational use.

You may only use this tool on networks you own or have written permission to audit.

❗ Illegal use is your responsibility.
	•	Do not attack public Wi-Fi or third-party networks.
	•	Doing so can result in criminal charges.
	•	The authors of this toolkit accept no liability for misuse, damage, or unlawful activity.

By using this software, you agree to this disclaimer.

⸻

🕶 License

This project is licensed under the MIT License.

⸻

Hack smart. Hack ethically. Stay neon.



