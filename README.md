![image](https://github.com/user-attachments/assets/98c1370a-47e6-4927-8484-9343c74c2ea5)

# 🧬 NeonCrack — Cyberpunk WPA/PMKID Cracking Toolkit

**NeonCrack** is a single-file, Python-based “red-team cockpit” that bundles the most common wireless- and network-penetration workflows into one neon-themed GUI. Think of it as a mash-up of Wifite-style Wi-Fi attacks, hostapd-mana rogue-AP trickery, and a lightweight nmap front-end—all stitched together so you can pivot from discovery to exploitation and finally to cracking without leaving the same window.

Who it’s for

Pentesters, CTFers, and hobbyists who already know the underlying tools but want a quick dashboard that:
	•	eliminates copy-pasting BSSIDs,
	•	auto-converts captures for cracking,
	•	and keeps everything in one terminal-friendly Tk window.

 Not a silver bullet
 
 NeonCrack calls the real tools under the hood—if your wireless adapter can’t inject, or if hostapd-mana isn’t in your repo, NeonCrack will fail. It’s a convenience layer, not a magic exploit kit.

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
sudo python3 neoncrack.py
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
sudo python3 neoncrack.py
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

Developed by Null_Lyfe

🙏 Special Thanks

NeonCrack is only possible because of an incredible ecosystem of open-source projects.
Huge respect to the engineers, researchers, and maintainers who built the tools we stand on NeonCrack wouldn’t exist without the open-source pioneers below.
Their tools do the heavy lifting—NeonCrack is just the glue.

```bash
Project Creators | Maintainers
aircrack-ng suite|Thomas d’Otreppe & contributors
hcxdumptool + hcxtools | ZerBea
hashcat | Jens “atom” Steube & team
Reaver / Wash | Craig Heffner · Tactical Network Solutions
Bully | Stef van der Zande
mdk4 | aircrack-ng team (built on Musket Teams’ mdk3)
hostapd-mana (KARMA)| Dominic “singe” White · Ian de Villiers
nmap | Gordon “Fyodor” Lyon & the Nmap Project
psutil | Giampaolo Rodolà
matplotlib | John D. Hunter † & dev team
```
Your code, research, and late-night bug fixes power every packet NeonCrack captures.
Thank you for sharing your brilliance with the community. <3

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



