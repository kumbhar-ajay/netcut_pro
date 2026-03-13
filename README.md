# Python NetCut Controller

An interactive, command-line network management and auditing tool written in Python. This script allows authorized users to scan their local subnet, identify connected devices (including Hostname and MAC Vendor), and selectively toggle their internet access using ARP cache poisoning.

**⚠️ Disclaimer:** This tool is strictly for educational purposes and authorized penetration testing. You must only run this on networks you own or have explicit, written permission to audit. The author is not responsible for any misuse or damage caused by this software.

---

## Features

* **Dynamic Interface Selection:** Automatically detects active network interfaces and resolves their associated IP and Gateway configurations.
* **Comprehensive Scanning:** Discovers local devices and attempts to resolve their Hostnames (via reverse DNS) and Hardware Vendors (via the MacVendors API).
* **Interactive CLI UI:** Color-coded, real-time terminal interface to view network states and manage target connections.
* **Multi-Threaded ARP Poisoning:** Isolates targets from the gateway using dedicated background threads, ensuring the main CLI remains responsive.
* **Graceful Restoration:** Intercepts shutdown signals (`Ctrl+C`) to automatically repair the ARP tables of all disconnected targets before exiting.

---

## Prerequisites

This script requires a Linux environment (such as Kali Linux or Ubuntu) and must be executed with **root privileges** to manipulate raw network sockets.

Ensure you have Python 3 installed, along with the required libraries.

---

## Installation

**1. Clone the repository**
```bash
git clone https://github.com/kumbhar-ajay/netcut_pro
cd netcut_pro
sudo python3 netcut.py

1. Select the Network Card
2. Select the IP_Address (toggle)
3. r- to rescan & q - Quit the Tools
