![image](https://github.com/user-attachments/assets/98c1370a-47e6-4927-8484-9343c74c2ea5)

# 🧬 NeonCrack — Cyberpunk WPA/PMKID Cracking Toolkit

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
Huge respect to the engineers, researchers, and maintainers who built the tools we stand on:
```bash
## 🔧 Special Thanks

NeonCrack was built on the powerful work of the open-source community. Much respect and thanks to the creators of these tools:

| Tool / Library                          | Lead Author(s) / Team                                   |
|----------------------------------------|----------------------------------------------------------|
| aircrack-ng suite                      | Thomas d’Otreppe and the aircrack-ng team               |
| hcxdumptool & hcxtools                 | ZerBea                                                  |
| hashcat                                | Jens “atom” Steube & contributors                       |
| Reaver & Wash                          | Craig Heffner / Tactical Network Solutions              |
| Bully                                  | Stef van der Zande                                      |
| mdk4                                   | aircrack-ng team (successor to mdk3 by Musket Teams)    |
| hostapd-mana (KARMA)                   | Dominic “singe” White & Ian de Villiers                 |
| nmap                                   | Gordon “Fyodor” Lyon & the Nmap Project                 |
| psutil (bandwidth stats)               | Giampaolo Rodolà                                        |
| matplotlib (graphing)                  | John D. Hunter † and the Matplotlib dev team            |
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



