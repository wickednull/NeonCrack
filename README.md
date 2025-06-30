# 🧬 NeonCrack v2 - Cyberpunk WPA Handshake Cracking Suite

**NeonCrack** is a sleek, cyberpunk-styled toolkit for cracking WPA/WPA2 handshakes with a powerful GUI interface. Built with `aircrack-ng`, `cap2hccapx`, and optional `hashid` support, this tool lets you analyze, convert, crack, and track captured handshakes — all from one neon-lit interface.

---

## ⚙️ Features

- 🔐 **WPA/WPA2 Handshake Cracking**
  - Uses `aircrack-ng` with custom wordlists
  - Real-time terminal output display

- 🔎 **Hash Identifier**
  - Detects hash types with regex and optional `hashid` CLI integration

- 🧹 **Capture Cleaner**
  - Converts `.cap/.pcap` files to `.hccapx` for Hashcat
  - Uses `cap2hccapx`

- 📊 **Stats Viewer**
  - Displays cracked passwords
  - Tracks cracking duration
  - Saves results to `cracked_results.txt`

- 🎨 **Cyberpunk GUI**
  - Dark theme with neon green & magenta aesthetics
  - Sidebar navigation and glowing terminal interface

---

## 🚀 Requirements

- Python 3.x
- [`aircrack-ng`](https://www.aircrack-ng.org/)
- `cap2hccapx` (from `hashcat-utils`)
- `python3-tk`
- Optional: `hashid` (`pip install hashid`)

Install dependencies on Kali/Ubuntu:
```bash
sudo apt install aircrack-ng hashcat-utils python3-tk
pip3 install hashid
