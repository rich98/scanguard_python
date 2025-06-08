# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#Version
VERSION = "0.4.27"
"""
Scan Guard Dog  Beta
A GUI-based passive network monitor written in Python with Scapy and Tkinter.
Detects ARP sweeps, ICMP/ICMPv6 pings, TCP/UDP port scans, and displays alerts in real-time.
Minimizes to the system tray and updates the icon color based on alert presence.
"""

# Standard Library Imports

import os  # Provides a way of using operating system dependent functionality
import sys  # Enables access to interpreter variables and functions (e.g., exiting, arguments)
import logging  # Standard logging facility for capturing application logs
import threading  # Enables concurrent execution using threads
import socket  # Low-level networking interface for IP communication
import signal  # Allows handling of asynchronous events like interrupts
import atexit  # Registers functions to be executed upon program termination
import subprocess  # Facilitates spawning new processes and connecting to their I/O
import platform  # Provides information about the system platform
from datetime import datetime, timedelta  # Date and time manipulation
from collections import defaultdict  # Dictionary subclass that provides default values
from queue import Queue, Empty  # Thread-safe queues and exception for empty queue handling
import tkinter as tk  # Base module for GUI development
from tkinter import ttk, scrolledtext, messagebox  # Enhanced widgets, scrollable text area, and dialogs
import tkinter.simpledialog as simpledialog  # Dialogs for user input
import urllib.request  # Enables fetching data across the web (e.g., HTTP requests)
import ctypes  # Allows calling functions in DLLs/shared libraries and low-level system access
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil  # Cross-platform library for system and process utilities (e.g., CPU, memory, disk usage)

# Third-Party Libraries

from scapy.all import (  # Powerful packet manipulation and network discovery library
    AsyncSniffer,  # Asynchronous packet sniffer
    TCP, IP, ICMP, ARP, UDP, IPv6, ICMPv6EchoRequest,  # Protocol-specific packet classes
    get_if_list,  # Retrieves list of network interfaces
    conf
)
import whois  # Module for querying WHOIS information about domains
from PIL import Image, ImageDraw  # Image manipulation and drawing (Pillow fork of PIL)
import pystray  # System tray icon support (cross-platform)
conf.verb = 0  # Suppress Scapy internal output (e.g., ARP reply logs)
# Logging

from logging.handlers import RotatingFileHandler  # Log handler that automatically rotates log files

def thread_safe(target, *args, **kwargs):
    def wrapper():
        try:
            target(*args, **kwargs)
        except Exception:
            logging.exception(f"Unhandled exception in thread: {target.__name__}")
    return wrapper

# print(f"[DEBUG] Running from: {__file__}")

# Privilege check
# Check if the operating system is not Windows
def check_privileges():
    if os.name == 'nt':
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logging.warning("Attempting to relaunch with administrator privileges.")
                params = ' '.join([f'"{arg}"' for arg in sys.argv])
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, params, None, 1
                )
                logging.info("Scan Guard Dog restarted with elevated privileges.")
                sys.exit(0)
        except Exception as e:
            sys.exit(f"❌ Unable to request admin rights: {e}")
    else:
        try:
            if os.geteuid() != 0:
                logging.warning("Attempting to relaunch with sudo...")
                os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        except AttributeError:
            sys.exit("❌ Cannot determine user privileges. Please run as root.")

log_queue = Queue()
alert_count = 0

class QueueHandler(logging.Handler):
    def emit(self, record):
        global alert_count
        log_entry = self.format(record)
        log_queue.put(log_entry)
        if record.levelno >= logging.WARNING:
            alert_count += 1

# Logger setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create a formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Queue handler for GUI log updates
queue_handler = QueueHandler()
queue_handler.setFormatter(formatter)
logger.addHandler(queue_handler)

# Add date and time to the log file name
current_date = datetime.now().strftime("%Y-%m-%d")
current_time = datetime.now().strftime("%H-%M-%S")
log_file_name = f"scan_guard_{current_date}_{current_time}.log"
log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), log_file_name)

try:
    file_handler = RotatingFileHandler(log_file_path, maxBytes=1024000, backupCount=3)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.info(f"Log file location: {log_file_path}")
except Exception as e:
    logging.warning(f"File logging disabled: {e}")

class NetworkMonitor:
    
    def __init__(self, iface=None, port_threshold=1, time_window=10, icmp_threshold=1, arp_threshold=1, udp_threshold=3, arp_enabled=True, icmp_enabled=True):
        # print(f"[DEBUG] ARP Enabled passed to NetworkMonitor: {arp_enabled}")
        self.iface = iface
        self.port_threshold = port_threshold
        self.icmp_threshold = icmp_threshold
        self.arp_threshold = arp_threshold
        self.udp_threshold = udp_threshold
        self.time_window = timedelta(seconds=time_window)
        self.local_ip = self.get_local_ip()
        self.local_ip_v4 = self.local_ip.get('ipv4')
        self.local_ip_v6 = self.local_ip.get('ipv6')

        self.scan_data = defaultdict(list)
        self.icmp_data = defaultdict(list)
        self.arp_data = defaultdict(list)
        self.udp_data = defaultdict(list)
        self.last_alert_times = {}  # Dictionary to track last alert per source
        self.alert_suppression_window = timedelta(seconds=10)  # Suppress same alert within 10 seconds
        self.sniffer = None
        self.packet_count = 0  # Track number of packets processed
        self.arp_enabled = arp_enabled
        self.icmp_enabled = icmp_enabled
        self.packet_timestamps = []
        self.active_ips = set()
        self.logged_ips = set()  # Tracks which IPs have already been logged
        self.active_ip_log_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"active_ips_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"
        )
        self.alert_counts = defaultdict(int)  # Track ARP, ICMP, TCP, UDP

    IDS_ABNORMALITIES = {
        "ARP_SWEEP": "ARP sweep or spoofing attempt detected.",
        "ICMP_SWEEP": "ICMP ping sweep detected.",
        "ICMPV6_SWEEP": "ICMPv6 echo sweep detected.",
        "TCP_SCAN": "TCP SYN port scan detected.",
        "UDP_SCAN": "UDP port scan detected.",
    }

    def log_abnormality(self, key, detail, level="warning"):
        if key not in self.IDS_ABNORMALITIES:
            return
        tag = f"[{key}]"
        message = f"{tag} {self.IDS_ABNORMALITIES[key]} {detail}"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Callback for GUI (if registered)
        if hasattr(self, "gui_callback") and callable(self.gui_callback):
            self.gui_callback({
                "time": now,
                "type": key,
                "source": detail.split()[0],
                "details": detail
            })

        if level == "warning":
            logging.warning(message)
        elif level == "error":
            logging.error(message)
        else:
            logging.info(message)

    def resolve_hostname(self, ip):
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return None

    def get_local_ip(self):
        try:
            hostname = socket.gethostname()
            ipv4 = socket.gethostbyname(hostname)
            # Attempt to get IPv6
            ipv6 = None
            for res in socket.getaddrinfo(hostname, None, socket.AF_INET6):
                addr = res[4][0]
                if addr and not addr.startswith("fe80"):  # Ignore link-local
                    ipv6 = addr
                    break
            return {'ipv4': ipv4, 'ipv6': ipv6}
        except Exception:
            return {'ipv4': '127.0.0.1', 'ipv6': None}
    
    def _should_log(self, alert_key):
        now = datetime.now()
        last_time = self.last_alert_times.get(alert_key)
        if not last_time or (now - last_time > self.alert_suppression_window):
            self.last_alert_times[alert_key] = now
            return True
        return False
    
    def cleanup_old_entries(self):
        now = datetime.now()

        def clean(data_dict):
            for key in list(data_dict.keys()):
                if not data_dict[key]:
                    continue
                if isinstance(data_dict[key][0], tuple):
                    data_dict[key] = [entry for entry in data_dict[key] if now - entry[0] < self.time_window]
                else:
                    data_dict[key] = [ts for ts in data_dict[key] if now - ts < self.time_window]
                if not data_dict[key]:
                    del data_dict[key]

        clean(self.scan_data)
        clean(self.icmp_data)
        clean(self.arp_data)
        clean(self.udp_data)

    def detect_scan(self, pkt):
        now = datetime.now()
        self.packet_timestamps.append(now)
        self.packet_timestamps = [ts for ts in self.packet_timestamps if (now - ts).total_seconds() < 1]

        # Track active source IPs
        if pkt.haslayer(IP):
            self.active_ips.add(pkt[IP].src)
        elif pkt.haslayer(ARP):
            self.active_ips.add(pkt[ARP].psrc)
        elif pkt.haslayer(IPv6):
            self.active_ips.add(pkt[IPv6].src)

        # ✅ Always attempt to log the IP (handles all 3 types)
        self._log_new_ip(pkt)

        self.packet_count += 1

        if pkt.haslayer(IP):
            self._check_tcp(pkt)
            if self.icmp_enabled:
                self._check_icmp(pkt)
            self._check_udp(pkt)
        elif pkt.haslayer(ARP):
            if self.arp_enabled:
                self._check_arp(pkt)
        elif pkt.haslayer(IPv6) and self.icmp_enabled:
            self._check_icmpv6(pkt)

    def _check_tcp(self, pkt):
        ip_layer = pkt[IP]
        now = datetime.now()
        if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02 and ip_layer.dst == self.local_ip_v4:
            src_ip = ip_layer.src
            dst_port = pkt[TCP].dport
            self.scan_data[src_ip].append((now, dst_port))
            self.scan_data[src_ip] = [(ts, port) for ts, port in self.scan_data[src_ip] if now - ts < self.time_window]
            unique_ports = set(port for ts, port in self.scan_data[src_ip])
            if len(unique_ports) >= self.port_threshold:
                hostname = self.resolve_hostname(src_ip)
                host_info = f"{src_ip} ({hostname})" if hostname else src_ip
                alert_key = f"tcp_scan_{src_ip}"
                if self._should_log(alert_key):
                    self.alert_counts["TCP"] += 1
                    self.log_abnormality("TCP_SCAN", f"Source: {host_info}, Ports: {sorted(unique_ports)}")
                    #logging.warning(f"TCP Scan detected from {host_info} on ports: {sorted(unique_ports)}")
                self.scan_data[src_ip].clear()

    def _check_icmp(self, pkt):
        ip_layer = pkt[IP]
        now = datetime.now()
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and ip_layer.dst == self.local_ip_v4:
            src_ip = ip_layer.src
            self.icmp_data[src_ip].append(now)
            self.icmp_data[src_ip] = [ts for ts in self.icmp_data[src_ip] if now - ts < self.time_window]
            if len(self.icmp_data[src_ip]) >= self.icmp_threshold:
                hostname = self.resolve_hostname(src_ip)
                host_info = f"{src_ip} ({hostname})" if hostname else src_ip
                alert_key = f"icmp_sweep_{src_ip}"
                if self._should_log(alert_key):
                    self.alert_counts["ICMP"] += 1
                    self.log_abnormality("ICMP_SWEEP", f"Source: {host_info}")
                    #logging.warning(f"Ping Sweep detected from {host_info}")
                self.icmp_data[src_ip].clear()

    def _check_udp(self, pkt):
        ip_layer = pkt[IP]
        now = datetime.now()
        if pkt.haslayer(UDP) and ip_layer.dst == self.local_ip_v4:
            src_ip = ip_layer.src
            dst_port = pkt[UDP].dport
            self.udp_data[src_ip].append((now, dst_port))
            self.udp_data[src_ip] = [(ts, port) for ts, port in self.udp_data[src_ip] if now - ts < self.time_window]
            unique_ports = set(port for ts, port in self.udp_data[src_ip])
            if len(unique_ports) >= self.udp_threshold:
                hostname = self.resolve_hostname(src_ip)
                host_info = f"{src_ip} ({hostname})" if hostname else src_ip
                alert_key = f"udp_scan_{src_ip}"
                if self._should_log(alert_key):
                    self.alert_counts["UDP"] += 1
                    self.log_abnormality("UDP_SCAN", f"Source: {host_info}, Ports: {sorted(unique_ports)}")
                    #logging.warning(f"UDP Scan detected from {host_info} on ports: {sorted(unique_ports)}")
                self.udp_data[src_ip].clear()

    def _check_arp(self, pkt):
        # print(f"[DEBUG] Entering _check_arp. Enabled? {self.arp_enabled}")
        if not self.arp_enabled:
            # print("[DEBUG] ARP detection is OFF. Skipping packet.")
            return
        if not self.arp_enabled:
            return  # Skip all ARP logging and detection

        now = datetime.now()
        try:
            if pkt.haslayer(ARP) and pkt[ARP].op == 1:
                src_mac = pkt[ARP].hwsrc
                src_ip = pkt[ARP].psrc
                self.arp_data[src_mac].append(now)
                self.arp_data[src_mac] = [ts for ts in self.arp_data[src_mac] if now - ts < self.time_window]
                logging.info(f"ARP Request from MAC: {src_mac} resolved to IP: {src_ip}")
                if len(self.arp_data[src_mac]) >= self.arp_threshold:
                    hostname = self.resolve_hostname(src_ip)
                    host_info = f"{src_ip} ({hostname})" if hostname else src_ip
                    alert_key = f"arp_sweep_{src_mac}"
                    if self._should_log(alert_key):
                        self.alert_counts["ARP"] += 1
                        self.log_abnormality("ARP_SWEEP", f"MAC: {src_mac}, IP: {host_info}")
                        #logging.warning(f"Possible ARP Sweep from MAC: {src_mac} (IP: {host_info})")
                    self.arp_data[src_mac].clear()
        except Exception as e:
            logging.error(f"Error processing ARP packet: {e}")

    def _check_icmpv6(self, pkt):
        now = datetime.now()
        if pkt.haslayer(ICMPv6EchoRequest):
            src_ip = pkt[IPv6].src                                  
            dst_ip = pkt[IPv6].dst
            if dst_ip == self.local_ip_v6:
                self.icmp_data[src_ip].append(now)
                self.icmp_data[src_ip] = [ts for ts in self.icmp_data[src_ip] if now - ts < self.time_window]
                if len(self.icmp_data[src_ip]) >= self.icmp_threshold:
                    hostname = self.resolve_hostname(src_ip)
                    host_info = f"{src_ip} ({hostname})" if hostname else src_ip
                    alert_key = f"icmpv6_sweep_{src_ip}"
                    if self._should_log(alert_key):
                        self.log_abnormality("ICMPV6_SWEEP", f"Source: {host_info}")
                    self.icmp_data[src_ip].clear()

    def set_arp_enabled(self, enabled):
        self.arp_enabled = enabled
        logging.info(f"ARP Detection {'enabled' if enabled else 'disabled'} during runtime.")

    def set_icmp_enabled(self, enabled):
        self.icmp_enabled = enabled
        logging.info(f"ICMP Detection {'enabled' if enabled else 'disabled'} during runtime.")             

    def start(self):
        try:
            self.sniffer = AsyncSniffer(filter="ip or ip6 or arp", prn=self.detect_scan, iface=self.iface, store=0)
            self.sniffer.start()

            # Log local IPs
            logging.info(f"Monitoring IPv4: {self.local_ip_v4}")
            if self.local_ip_v6:
                logging.info(f"Monitoring IPv6: {self.local_ip_v6}")
            else:
                logging.warning("IPv6 address not detected. IPv6 scanning may be incomplete.")
                logging.info(f"Active IPs will be logged to: {self.active_ip_log_file}")
            logging.info(f"Started monitoring on interface: {self.iface or 'all interfaces'}")
        except Exception as e:
            logging.error(f"[FATAL] Sniffing failed: {e}")

    def stop(self):
        if self.sniffer:
            try:
                self.sniffer.stop()
                logging.info("Sniffer stopped.")
            except Exception as e:
                logging.warning(f"Error stopping sniffer: {e}")
    
    def _log_new_ip(self, pkt):
        ip = None

        if pkt.haslayer(IP):
            ip = pkt[IP].src
        elif pkt.haslayer(ARP):
            ip = pkt[ARP].psrc
        elif pkt.haslayer(IPv6):
            ip = pkt[IPv6].src

        if ip:
            if ip not in self.logged_ips:
                self.logged_ips.add(ip)
                try:
                    with open(self.active_ip_log_file, "a") as f:
                        f.write(ip + "\n")
                except Exception as e:
                    logging.error(f"Failed to write IP to active IP log: {e}")

def scan_port(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except Exception:
        pass
    return None               

def list_open_ports(ip, port_range=(1, 1024), timeout=0.3, max_workers=None):
    total_ports = port_range[1] - port_range[0] + 1

    # Dynamically determine thread count
    if max_workers is None:
        max_workers = min(100, max(10, total_ports // 10))

    logging.info(f"Scanning {total_ports} TCP ports on {ip} using {max_workers} threads...")

    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in range(port_range[0], port_range[1] + 1)}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    if open_ports:
        logging.info(f"Open ports on {ip}: {', '.join(map(str, sorted(open_ports)))}")
    else:
        logging.info(f"No open ports found on {ip} in range {port_range[0]}–{port_range[1]}.")

class ToggleSwitch(tk.Canvas):
    def __init__(self, parent, text, variable, command=None, **kwargs):
        super().__init__(parent, width=160, height=30, bg=parent['bg'], highlightthickness=0, **kwargs)
        self.variable = variable
        self.command = command
        self.text = text

        # Adjusted rectangle and switch coordinates
        self.rect = self.create_rectangle(5, 5, 55, 25, outline="", fill="#444")
        self.switch = self.create_oval(5, 5, 25, 25, fill="red", outline="gray")
        self.label = self.create_text(65, 15, text=text, anchor="w", fill="white", font=("Arial", 10))

        self.tag_raise(self.switch)
        self.bind("<Button-1>", self.toggle)
        self.update_switch()

    def toggle(self, event=None):
        self.variable.set(not self.variable.get())
        self.update_switch()
        if self.command:
            self.command()

    def update_switch(self):
        if self.variable.get():
            self.itemconfig(self.switch, fill="green")
            self.coords(self.switch, 35, 5, 55, 25)
        else:
            self.itemconfig(self.switch, fill="red")
            self.coords(self.switch, 5, 5, 25, 25)
    
# GUI-based Application Class
class NetworkMonitorApp:

    def __init__(self, root):
        self.root = root
        self.monitor = None
        self.sniff_thread = None
        self.tray_icon = None


    def check_for_updates(self):
        update_url = "https://raw.githubusercontent.com/rich98/scanguard_python/refs/heads/main/VERSION"
        current_version = VERSION

        def _check():
            try:
                with urllib.request.urlopen(update_url, timeout=5) as response:
                    latest_version = response.read().decode("utf-8").strip()
                    if latest_version > current_version:
                        self.root.after(0, lambda: messagebox.showinfo(
                            "Update Available",
                            f"A new version ({latest_version}) is available.\nYou are running {current_version}."
                        ))
            except Exception as e:
                logging.warning(f"Update check failed: {e}")

        threading.Thread(target=thread_safe(_check), daemon=True).start()
    def toggle_theme(self):
        is_dark = self.dark_mode.get()

        bg = "#2e2e2e" if is_dark else "#f0f0f0"
        fg = "white" if is_dark else "black"
        console_bg = "#1e1e1e"  # Always dark background
        console_fg = "#00ff00"  # Always bright green text
        self.root.configure(bg=bg)
        self.button_frame.configure(bg=bg)

        # Apply to log display
        self.log_display.configure(bg=console_bg, fg=console_fg, insertbackground=fg)

        # Apply to alert label
        self.alert_label.configure(bg=bg, fg=fg)

        # Update toggle frame background
        for child in self.root.winfo_children():
            if isinstance(child, tk.Frame):
                child.configure(bg=bg)

        # Update ttk styles
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TButton", background=bg, foreground=fg)
        style.configure("TCombobox", fieldbackground=bg, background=bg, foreground=fg)
        style.configure("Close.TButton", background="#880000" if is_dark else "#aa0000", foreground="#ffffff")
    def toggle_arp(self):
        if self.monitor:
            self.monitor.set_arp_enabled(self.arp_enabled.get())

    def toggle_icmp(self):
        if self.monitor:
            self.monitor.set_icmp_enabled(self.icmp_enabled.get())

    def __init__(self, root):
        self.root = root
        self.monitor = None
        self.sniff_thread = None
        self.tray_icon = None

        root.title(f"Scan Guard Dog {VERSION} for Windows")
        root.geometry("1040x768")
        root.configure(bg="#2e2e2e")

        # === Menu Bar Setup ===
        menu_bar = tk.Menu(self.root)

        # Settings Menu
        settings_menu = tk.Menu(menu_bar, tearoff=0)
        settings_menu.add_command(label="Thresholds...", command=self.open_settings_window)
        menu_bar.add_cascade(label="Settings", menu=settings_menu)

        # Apply Menu to Root Window
        self.root.config(menu=menu_bar)
        # === End Menu Bar Setup ===

         # Style setup
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TButton", background="#444", foreground="#fff")
        style.configure("TCombobox", fieldbackground="#333", background="#444", foreground="#fff")
        style.configure("Close.TButton", background="#880000", foreground="#ffffff")  # Red close button

        # Interface selection
        self.iface_var = tk.StringVar()
        interfaces = ["[All Interfaces]"] + get_if_list()
        self.interface_combo = ttk.Combobox(root, textvariable=self.iface_var, values=interfaces, state="readonly")
        self.interface_combo.set("[All Interfaces]")
        self.interface_combo.pack(fill='x', padx=10, pady=5)

        # Detection toggle state variables
        self.arp_enabled = tk.BooleanVar(value=True)
        self.icmp_enabled = tk.BooleanVar(value=True)
        self.dark_mode = tk.BooleanVar(value=True)

        # Toggle switches now appear above the buttons
        toggle_frame = tk.Frame(root, bg="#2e2e2e")
        toggle_frame.pack(fill='x', padx=10, pady=(0, 5))

        ToggleSwitch(toggle_frame, "ARP Detection", self.arp_enabled, command=self.toggle_arp).grid(row=0, column=0, padx=20)
        ToggleSwitch(toggle_frame, "ICMP Detection", self.icmp_enabled, command=self.toggle_icmp).grid(row=0, column=1, padx=20)
        ToggleSwitch(toggle_frame, "Dark Mode", self.dark_mode, command=self.toggle_theme).grid(row=0, column=2, padx=20)


        # Button section frame
        self.button_frame = tk.Frame(root, bg="#2e2e2e")
        self.button_frame.pack(fill='x', padx=10, pady=(5, 0), expand=False)

       # Top row buttons      
        self.start_button = ttk.Button(self.button_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.stop_button = ttk.Button(self.button_frame, text="Stop Monitoring", command=self.stop_monitoring)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.scan_button = ttk.Button(self.button_frame, text="My open Ports", command=self.scan_ports)
        self.scan_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
    
        self.firewall_button = ttk.Button(self.button_frame, text="Open Firewall", command=self.open_firewall)
        self.firewall_button.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        self.close_button = ttk.Button (self.button_frame, text="Kill Switch", command=self.exit_app_direct, style="Close.TButton")
        self.close_button.grid(row=0, column=4, padx=5, pady=5, sticky="ew")

        # Equal weight for all three columns
        for i in range(5):
            self.button_frame.grid_columnconfigure(i, weight=2)
        
        # Second row buttons (formatted like top row)
        self.tray_button = ttk.Button(self.button_frame, text="Minimize to Tray", command=self.minimize_to_tray)
        self.tray_button.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        self.copy_button = ttk.Button(self.button_frame, text="Copy Logs to Clipboard", command=self.copy_logs)
        self.copy_button.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        self.clear_button = ttk.Button(self.button_frame, text="Clear Console", command=self.clear_console)
        self.clear_button.grid(row=1, column=2, padx=5, pady=5, sticky="ew")

        self.whois_button = ttk.Button(self.button_frame, text="Whois", command=self.open_whois_console)
        self.whois_button.grid(row=1, column=3, padx=5, pady=5, sticky="ew")

        self.export_button = ttk.Button(self.button_frame, text="Export Logs", command=self.export_logs)
        self.export_button.grid(row=1, column=4, padx=5, pady=5, sticky="ew")
        
        # Spacer
        tk.Frame(self.root, height=5, bg="#2e2e2e").pack(fill='x')

        self.alert_label = tk.Label(self.root, text="Alerts: 0", bg="#2e2e2e", fg="white")
        self.alert_label.pack(pady=5)
        self.stats_label = tk.Label(self.root, text="Initializing Stats...", bg="#2e2e2e", fg="white", font=("Arial", 10))
        self.stats_label.pack(pady=(0, 5))

        self.log_display = scrolledtext.ScrolledText(self.root, state='disabled', height=20, bg="#1e1e1e", fg="#00ff00", insertbackground="white")
        self.log_display.tag_config("warning", foreground="#FF5555")   # Red
        self.log_display.tag_config("ping", foreground="#F8FAF6")      # White
        self.log_display.tag_config("arp", foreground="#FFFF66")       # Yellow
        self.log_display.tag_config("icmpv6", foreground="#FF66FF")    # Magenta
        self.log_display.tag_config("info", foreground="#66B2FF")      # Blue
        self.log_display.tag_config("error", foreground="#FF4500")     # Orange-Red
        self.log_display.tag_config("abnormality", foreground="#C586C0")  # Purple
        self.log_display.pack(fill='both', expand=True, padx=10, pady=10)


        # Create a frame to hold the table and scrollbar
        table_frame = tk.Frame(self.root, bg="#2e2e2e")
        table_frame.pack(fill='both', expand=False, padx=10, pady=(0, 10))

        # Add vertical scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        # Create the Treeview inside the frame
        self.abnormality_tree = ttk.Treeview(
            table_frame,
            columns=("Time", "Type", "Source", "Details"),
            show="headings",
            yscrollcommand=scrollbar.set,
            height=12
        )

        # Configure the scrollbar to control the Treeview
        scrollbar.config(command=self.abnormality_tree.yview)

        # Define table columns and layout
        self.abnormality_tree.heading("Time", text="Time")
        self.abnormality_tree.heading("Type", text="Type")
        self.abnormality_tree.heading("Source", text="Source")
        self.abnormality_tree.heading("Details", text="Details")

        self.abnormality_tree.column("Time", width=150, anchor="w")
        self.abnormality_tree.column("Type", width=100, anchor="w")
        self.abnormality_tree.column("Source", width=150, anchor="w")
        self.abnormality_tree.column("Details", width=500, anchor="w")

        self.abnormality_tree.pack(side="left", fill="both", expand=True)
            
        
        #check for updates
        self.check_for_updates()

        self.update_log()
        self.update_stats()

    def create_image(self, color="green"):
        image = Image.new('RGB', (64, 64), color='black')
        draw = ImageDraw.Draw(image)
        draw.rectangle((16, 16, 48, 48), fill=color)
        return image

    def copy_logs(self):
        self.root.clipboard_clear()
        log_text = self.log_display.get("1.0", tk.END).strip()
        self.root.clipboard_append(log_text)
        self.root.update()

    def add_abnormality_to_grid(self, entry):
        def insert_and_scroll():
            # Insert the new row
            row_id = self.abnormality_tree.insert("", "end", values=(
                entry["time"],
                entry["type"],
                entry["source"],
                entry["details"]
            ))
            # Automatically scroll to the latest entry
            self.abnormality_tree.see(row_id)

        self.root.after(0, insert_and_scroll)

    def export_logs(self):
        log_text = self.log_display.get("1.0", tk.END).strip()

        # Define and create the export directory
        export_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exports")
        os.makedirs(export_dir, exist_ok=True)

        # Construct the export filename with timestamp
        filename = f"scan_guard_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(export_dir, filename)

        try:
            with open(filepath, "w") as f:
                f.write(log_text)
            logging.info(f"Log exported to {filepath}")
            # Optional: show success message to user
            messagebox.showinfo("Export Complete", f"Logs saved to:\n{filepath}")
        except Exception as e:
            logging.error(f"Failed to export logs: {e}")
            messagebox.showerror("Export Failed", f"An error occurred:\n{e}")

    def clear_console(self):
        global alert_count
        alert_count = 0
        if self.monitor:
            self.monitor.packet_count = 0  # Reset packet counter too
            self.update_alert_label()  # Update the label for both values   
            self.log_display.configure(state='normal')  # Enable editing
            self.log_display.delete("1.0", tk.END)
            self.log_display.configure(state='disabled')
            self.update_alert_label()  # Update GUI label

    def create_tray_icon(self):
        image = self.create_image()
        self.tray_icon = pystray.Icon("Scan Guard Dog", image, "Scan Guard Dog", menu=pystray.Menu(
            pystray.MenuItem("Restore", self.show_window),
            pystray.MenuItem("Exit", self.exit_app)
        ))
        threading.Thread(target=thread_safe(self.tray_icon.run), daemon=True).start()

    def minimize_to_tray(self):
        self.root.withdraw()
        self.create_tray_icon()

    def show_window(self, icon=None, item=None):
        self.tray_icon.stop()
        self.root.after(0, self.root.deiconify)

    def exit_app(self, icon=None, item=None):
        self.tray_icon.stop()
        self.root.quit()

    def start_monitoring(self):
        global alert_count
        alert_count = 0
        self.update_alert_label()
        self.start_button.config(state="disabled")
        iface = None if self.iface_var.get() == "[All Interfaces]" else self.iface_var.get()

        # Pass user toggle settings
        # print(f"[DEBUG] GUI toggle state for ARP Detection: {self.arp_enabled.get()}")
        self.monitor = NetworkMonitor(
            iface=iface,
            arp_enabled=self.arp_enabled.get(),
            icmp_enabled=self.icmp_enabled.get()
        )

        # Hook the GUI callback for real-time abnormality tracking
        self.monitor.gui_callback = self.add_abnormality_to_grid

        self.sniff_thread = threading.Thread(target=self.monitor.start, daemon=True)
        self.sniff_thread.start()
        logging.info("Monitoring started.")
        if self.tray_icon:
            self.tray_icon.icon = self.create_image("green")


    def stop_monitoring(self):
        if self.monitor:
            self.monitor.stop()
        logging.info("Monitoring stopped. Thank you for using Scan Guard Dog")
        self.copy_button.config(state="normal")
        self.start_button.config(state="normal")

    def scan_ports(self):
        ip = self.monitor.local_ip if self.monitor else NetworkMonitor().get_local_ip()
        threading.Thread(target=thread_safe(list_open_ports, ip), daemon=True).start()

    def update_alert_label(self):
        packet_count = self.monitor.packet_count if self.monitor else 0
        self.alert_label.config(text=f"Alerts: {alert_count} | Packets: {packet_count}")
        if alert_count > 0 and self.tray_icon:
            self.tray_icon.icon = self.create_image("yellow")
    
    def update_stats(self):
        if self.monitor:
            pkt_rate = len(self.monitor.packet_timestamps)
            active_ips = len(self.monitor.active_ips)
            arp_alerts = self.monitor.alert_counts.get("ARP", 0)
            icmp_alerts = self.monitor.alert_counts.get("ICMP", 0)
            tcp_alerts = self.monitor.alert_counts.get("TCP", 0)
            udp_alerts = self.monitor.alert_counts.get("UDP", 0)

            self.stats_label.config(
                text=f"Active IPs: {active_ips} | Pkts/sec: {pkt_rate} | ARP: {arp_alerts} | ICMP: {icmp_alerts} | TCP: {tcp_alerts} | UDP: {udp_alerts}"
            )

        self.root.after(1000, self.update_stats)

    def update_log(self):
        try:
            while True:
                msg = log_queue.get(timeout=0.2)
                self.log_display.configure(state='normal')

                # Color-coded pattern matching
                if "Scanning for open TCP ports" in msg or "Open ports on" in msg or "No open ports found" in msg:
                    self.log_display.insert(tk.END, msg + '\n', "info")
                elif "Ping Sweep detected" in msg:
                    self.log_display.insert(tk.END, msg + '\n', "ping")
                elif any(tag in msg for tag in ["[ARP_SWEEP]", "[ICMP_SWEEP]", "[ICMPV6_SWEEP]", "[TCP_SCAN]", "[UDP_SCAN]"]):
                    self.log_display.insert(tk.END, msg + '\n', "abnormality")
                elif "Possible ARP Sweep" in msg:
                    self.log_display.insert(tk.END, msg + '\n', "arp")
                elif "ICMPv6 Echo Sweep detected" in msg:
                    self.log_display.insert(tk.END, msg + '\n', "icmpv6")
                elif "WARNING" in msg:
                    self.log_display.insert(tk.END, msg + '\n', "warning")
                elif "ERROR" in msg or "FATAL" in msg:
                    self.log_display.insert(tk.END, msg + '\n', "error")
                else:
                    self.log_display.insert(tk.END, msg + '\n')

                self.log_display.configure(state='disabled')
                self.log_display.yview(tk.END)
                self.update_alert_label()
        except Empty:
            pass
        finally:
            self.log_display.after(1000, self.update_log)

    def open_whois_console(self):
        ip_or_domain = simpledialog.askstring("Whois Lookup", "Enter IP address or domain:")
        if not ip_or_domain:
            return

        whois_window = tk.Toplevel(self.root)
        whois_window.title(f"Whois Results for {ip_or_domain}")
        whois_window.geometry("700x500")
        whois_window.configure(bg="#1e1e1e")

        text_area = scrolledtext.ScrolledText(whois_window, wrap=tk.WORD, bg="#1e1e1e", fg="#00ff00", insertbackground="white")
        text_area.pack(fill='both', expand=True, padx=10, pady=10)
        text_area.insert(tk.END, f"Looking up {ip_or_domain}...\n")
        text_area.configure(state='disabled')

        def run_python_whois():
            try:
                result = whois.whois(ip_or_domain)
                output = "\n".join(f"{key}: {value}" for key, value in result.items() if value)
            except Exception as e:
                output = f"Error performing WHOIS lookup: {e}"

            def display_result():
                text_area.configure(state='normal')
                text_area.delete("1.0", tk.END)
                text_area.insert(tk.END, output)
                text_area.configure(state='disabled')

            self.root.after(0, display_result)

        # Wrapped in thread_safe to ensure any exception is logged
        threading.Thread(target=thread_safe(run_python_whois), daemon=True).start()
        
    def open_firewall(self):
            if platform.system() == "Windows":
                try:
                    subprocess.Popen(["control.exe", "/name", "Microsoft.WindowsFirewall"])
                    logging.info("Opened Windows Firewall settings.")
                except Exception as e:
                    logging.error(f"Failed to open Windows Firewall: {e}")
            else:
                logging.warning("Firewall UI opening is only supported on Windows.")

    def open_settings_window(self):
        if not self.monitor:
            messagebox.showwarning("Monitor Not Running", "Start monitoring first to adjust thresholds.")
            return

        settings = tk.Toplevel(self.root)
        settings.title("Threshold Settings")
        settings.geometry("300x250")
        settings.configure(bg="#2e2e2e")

        entry_fields = {}

        def save_settings():
            try:
                self.monitor.port_threshold = int(entry_fields["tcp"].get())
                self.monitor.icmp_threshold = int(entry_fields["icmp"].get())
                self.monitor.udp_threshold = int(entry_fields["udp"].get())
                self.monitor.arp_threshold = int(entry_fields["arp"].get())
                logging.info("Threshold settings updated by user.")
                settings.destroy()
            except ValueError:
                messagebox.showerror("Input Error", "All thresholds must be integers.")

        for label, default, key in [
            ("TCP Port Threshold:", self.monitor.port_threshold, "tcp"),
            ("ICMP Packet Threshold:", self.monitor.icmp_threshold, "icmp"),
            ("UDP Port Threshold:", self.monitor.udp_threshold, "udp"),
            ("ARP Request Threshold:", self.monitor.arp_threshold, "arp")
        ]:
            tk.Label(settings, text=label, bg="#2e2e2e", fg="white").pack(pady=3)
            entry = tk.Entry(settings)
            entry.insert(0, str(default))
            entry.pack()
            entry_fields[key] = entry


        ttk.Button(settings, text="Save", command=save_settings).pack(pady=10)

    def exit_app_direct(self):
        confirm = messagebox.askyesno("Exit Application", "Are you sure you want to exit?")
        if confirm:
            if self.monitor:
                self.monitor.stop()
            logging.info("Application closed directly by user.")
            self.root.quit()

# Launch
if __name__ == "__main__":
    check_privileges()  # Enforce root/admin privileges at launch
    logging.info("Scan Guard Dog launched successfully.")
    
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    app.start_monitoring()

    def cleanup():
        if app.monitor:
            app.monitor.stop()
        logging.info("Application exiting: Sniffer stopped.")

    atexit.register(cleanup)
    signal.signal(signal.SIGINT, lambda signum, frame: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))

    try:
        root.mainloop()
    finally:
        cleanup()
