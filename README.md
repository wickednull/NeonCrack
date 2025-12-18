# 🧬 NeonCrack — Cyberpunk WPA/PMKID Cracking Toolkit

![image](https://github.com/user-attachments/assets/98c1370a-47e6-4927-8484-9343c74c2ea5)

**NeonCrack** is a single-file, Python-based “red-team cockpit” that bundles the most common wireless- and network-penetration workflows into one neon-themed GUI. Think of it as a mash-up of Wifite-style Wi-Fi attacks, hostapd-mana rogue-AP trickery, and a lightweight nmap front-end—all stitched together so you can pivot from discovery to exploitation and finally to cracking without leaving the same window.

### Who it’s for

Pentesters, CTFers, and hobbyists who already know the underlying tools but want a quick dashboard that:
•eliminates copy-pasting BSSIDs,
•auto-converts captures for cracking,
•and keeps everything in one terminal-friendly Tk window.

### Not a silver bullet
 
NeonCrack calls the real tools under the hood—if your wireless adapter can’t inject, or if hostapd-mana isn’t in your repo, NeonCrack will fail. It’s a convenience layer, not a magic exploit kit.

---

## ⚡ Features

### 📡 Wireless Capture & Scanning
*   **Targeted Scanning:** Discover nearby Wi-Fi networks and their details (SSID, BSSID, Channel, Encryption).
*   **PMKID Handshake Capture:** Capture PMKID handshakes via `hcxdumptool` and `airodump-ng`.
*   **WPA/WPA2 Handshake Capture:** Efficiently capture 4-way handshakes for offline cracking.
*   **Save Captures:** Automatically saves `.pcap` and `.cap` files to `neoncrack_captures/`.

### 🔑 Password Cracking
*   **WPA Handshake Cracker:** Load `.cap` or `.pcap` handshake files.
*   **Custom Wordlists:** Use any custom wordlist (e.g., `rockyou.txt`).
*   **Aircrack-ng Integration:** Crack with `aircrack-ng` and view results live.
*   **Hashcat Integration:** Leverage GPU-accelerated cracking with `hashcat` for WPA/WPA2 handshakes (requires manual conversion to `.hccapx` or `.22000` format).
*   **Wordlist Generation:** Generate custom wordlists for brute-force and dictionary attacks.

### ⚔️ Advanced Attack Vectors
*   **Deauthentication Attacks:** Disconnect clients from target networks to force handshake re-capture.
*   **Evil Twin Attacks:** Set up malicious access points to trick users into connecting and revealing credentials.
*   **Pixie Dust Attacks:** Exploit WPS vulnerabilities using `reaver` to recover Wi-Fi passwords.
*   **Karma & Mana Attacks:** Advanced rogue AP attacks using `hostapd-mana` for client-side exploitation.
*   **Rogue AP Setup:** Create controlled rogue access points for various testing scenarios.
*   **Phishing Attacks:** Integrate with tools like `wifiphisher` for credential harvesting.

### 🛠️ Utilities
*   **Hash Identifier:** Detect hash types (MD5, SHA1, SHA256, WPA, bcrypt, etc.) using regex and optional CLI tool `hashid`.
*   **Capture Cleaner:** Convert `.pcapng` or `.cap` to `.hccapx` using `hcxpcapngtool` for `hashcat` compatibility.
*   **Dependency Checker:** Automatically verifies the presence of essential tools.
*   **Interface Management:** Seamlessly switch wireless adapters between monitor and managed modes.
*   **Vulnerability Assessment:** Scan for common network vulnerabilities.

### 📊 Stats & Logging
*   View cracked password stats.
*   Save successful keys to `cracked_results.txt`.

---

### 🔧 Dependencies

NeonCrack relies on several external tools and Python libraries.

**System Dependencies:**
```bash
sudo apt update
sudo apt install aircrack-ng hcxtools reaver bully bettercap wifiphisher hostapd dnsmasq php scapy python3-tk xterm
```

**Python Dependencies:**
```bash
pip3 install hashid # optional, for enhanced hash identification
# You may also need to install other Python libraries if not already present:
# pip3 install colorama tqdm requests
```
*Note: A `requirements.txt` file is not currently in the repository. You may need to create one based on the imports in `neoncrack.py` if you plan to distribute this tool widely.*

### 🧠 Running NeonCrack

NeonCrack often requires root privileges to perform network operations.

#### 🔸 Standard Linux Systems:
```bash
sudo python3 neoncrack.py
```

#### 🔸 On NetHunter Pro (e.g. PinePhone):
1.  **Boot into Kali NetHunter Pro**
2.  **Ensure monitor mode works**
    Test your WiFi adapter:
    ```bash
    iwconfig
    sudo airmon-ng start wlan1  # replace with correct interface
    ```
3.  **Give X11 Permissions (Important)**
    On NetHunter Pro with GUI, run this if you get display issues:
    ```bash
    xhost +SI:localuser:root
    ```
4.  **Run the GUI Script:**
    ```bash
    sudo python3 neoncrack.py
    ```

#### ⚠️ NetHunter Pro Special Notes
*   For Alfa USB adapters (e.g., AC600), ensure drivers are working.
*   You may need a powered OTG hub for full performance.
*   Test monitor mode with:
    ```bash
    sudo airmon-ng start wlan1
    sudo airodump-ng wlan1mon
    ```
    If NeonCrack shows no networks, verify:
    *   Monitor mode is active.
    *   You selected the correct interface.
    *   You gave X11 permission (`xhost +`).

---

### 💡 Usage

NeonCrack is designed to be intuitive. Use the `--help` flag to see all available commands and options.

```bash
sudo python3 neoncrack.py --help
```

#### Common Examples:

*   **Scan for Wi-Fi Networks:**
    ```bash
    sudo python3 neoncrack.py --scan -i wlan0
    ```

*   **Capture WPA/WPA2 Handshake:**
    ```bash
    sudo python3 neoncrack.py --capture-handshake -i wlan0 --target-bssid AA:BB:CC:DD:EE:FF --channel 6 --output-file my_handshake.cap
    ```

*   **Crack a Handshake using Aircrack-ng:**
    ```bash
    sudo python3 neoncrack.py --crack -f my_handshake.cap --wordlist /path/to/your/wordlist.txt --cracker aircrack
    ```

*   **Perform a Deauthentication Attack:**
    ```bash
    sudo python3 neoncrack.py --deauth -i wlan0 --target-bssid AA:BB:CC:DD:EE:FF --client-mac 11:22:33:44:55:66 --packets 100
    ```

*   **Start an Evil Twin Attack:**
    ```bash
    sudo python3 neoncrack.py --evil-twin -i wlan0 --ssid "Free_WiFi" --redirect-url http://phishing.com
    ```

*   **Perform a PMKID Attack:**
    ```bash
    sudo python3 neoncrack.py --pmkid -i wlan0 --output-file pmkid_capture.pcapng
    ```

*   **Perform a Pixie Dust Attack:**
    ```bash
    sudo python3 neoncrack.py --pixie-dust -i wlan0 --target-bssid AA:BB:CC:DD:EE:FF
    ```

*   **Check Dependencies:**
    ```bash
    python3 neoncrack.py --check-dependencies
    ```

---

### 📸 Screenshots & Demos

*(Screenshots or GIFs demonstrating NeonCrack's output and functionality will be added here soon!)*

---

### 🤝 Contributing

Contributions are welcome! If you have suggestions for improvements, new features, or bug fixes, please feel free to:

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/YourFeature`).
3.  Make your changes.
4.  Commit your changes (`git commit -m 'Add some feature'`).
5.  Push to the branch (`git push origin feature/YourFeature`).
6.  Open a Pull Request.

---

### 🙏 Special Thanks

NeonCrack is only possible because of an incredible ecosystem of open-source projects.
Huge respect to the engineers, researchers, and maintainers who built the tools we stand on. NeonCrack wouldn’t exist without the open-source pioneers below. Their tools do the heavy lifting—NeonCrack is just the glue.

```
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

---

### 📄 License

This project is licensed under the MIT License.

---

### ⚠️ Disclaimer

NeonCrack is intended solely for legal security testing and educational use.

You may only use this tool on networks you own or have written permission to audit.

❗ Illegal use is your responsibility.
*   Do not attack public Wi-Fi or third-party networks.
*   Doing so can result in criminal charges.
*   The authors of this toolkit accept no liability for misuse, damage, or unlawful activity.

By using this software, you agree to this disclaimer.

---
Hack smart. Hack ethically. Stay neon.

**Developed by Null_Lyfe**
