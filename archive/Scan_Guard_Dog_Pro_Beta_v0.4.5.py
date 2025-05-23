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
#Version.0.4.5
"""
Scan Guard Dog  Beta
A GUI-based passive network monitor written in Python with Scapy and Tkinter.
Detects ARP sweeps, ICMP/ICMPv6 pings, TCP/UDP port scans, and displays alerts in real-time.
Minimizes to the system tray and updates the icon color based on alert presence.
"""

import os
import sys
import logging
import threading
import socket
import signal
import atexit
import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import (
    AsyncSniffer, TCP, IP, ICMP, ARP, UDP, IPv6, ICMPv6EchoRequest, get_if_list
)
from collections import defaultdict
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty
import pystray
from PIL import Image, ImageDraw
from logging.handlers import RotatingFileHandler
from tkinter import Toplevel
from PIL import ImageTk

# Privilege check
if os.name != 'nt' and os.geteuid() != 0:
    sys.exit("This program must be run as root.")

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
queue_handler = QueueHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
queue_handler.setFormatter(formatter)
logger.addHandler(queue_handler)

try:
    file_handler = RotatingFileHandler("scan_guard.log", maxBytes=1024000, backupCount=3)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
except Exception as e:
    logging.warning(f"File logging disabled: {e}")

class NetworkMonitor:
    def __init__(self, iface=None, port_threshold=1, time_window=10, icmp_threshold=2, arp_threshold=5, udp_threshold=3):
        self.iface = iface
        self.port_threshold = port_threshold
        self.icmp_threshold = icmp_threshold
        self.arp_threshold = arp_threshold
        self.udp_threshold = udp_threshold
        self.time_window = timedelta(seconds=time_window)

        self.local_ip = self.get_local_ip()

        self.scan_data = defaultdict(list)
        self.icmp_data = defaultdict(list)
        self.arp_data = defaultdict(list)
        self.udp_data = defaultdict(list)

        self.sniffer = None

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'

    def detect_scan(self, pkt):
        if pkt.haslayer(IP):
            self._check_tcp(pkt)
            self._check_icmp(pkt)
            self._check_udp(pkt)
        elif pkt.haslayer(ARP):
            self._check_arp(pkt)
        elif pkt.haslayer(IPv6):
            self._check_icmpv6(pkt)

    def _check_tcp(self, pkt):
        ip_layer = pkt[IP]
        now = datetime.now()
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S" and ip_layer.dst == self.local_ip:
            src_ip = ip_layer.src
            dst_port = pkt[TCP].dport
            self.scan_data[src_ip].append((now, dst_port))
            self.scan_data[src_ip] = [(ts, port) for ts, port in self.scan_data[src_ip] if now - ts < self.time_window]
            unique_ports = set(port for ts, port in self.scan_data[src_ip])
            if len(unique_ports) >= self.port_threshold:
                logging.warning(f"TCP Port Scan detected from {src_ip} on ports: {sorted(unique_ports)}")
                self.scan_data[src_ip].clear()

    def _check_icmp(self, pkt):
        ip_layer = pkt[IP]
        now = datetime.now()
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and ip_layer.dst == self.local_ip:
            src_ip = ip_layer.src
            self.icmp_data[src_ip].append(now)
            self.icmp_data[src_ip] = [ts for ts in self.icmp_data[src_ip] if now - ts < self.time_window]
            if len(self.icmp_data[src_ip]) >= self.icmp_threshold:
                logging.warning(f"Ping Sweep detected from {src_ip}")
                self.icmp_data[src_ip].clear()

    def _check_udp(self, pkt):
        ip_layer = pkt[IP]
        now = datetime.now()
        if pkt.haslayer(UDP) and ip_layer.dst == self.local_ip:
            src_ip = ip_layer.src
            dst_port = pkt[UDP].dport
            self.udp_data[src_ip].append((now, dst_port))
            self.udp_data[src_ip] = [(ts, port) for ts, port in self.udp_data[src_ip] if now - ts < self.time_window]
            unique_ports = set(port for ts, port in self.udp_data[src_ip])
            if len(unique_ports) >= self.udp_threshold:
                logging.warning(f"UDP Scan suspected from {src_ip} on ports: {sorted(unique_ports)}")
                self.udp_data[src_ip].clear()

    def _check_arp(self, pkt):
        now = datetime.now()
        try:
            if pkt.haslayer(ARP) and pkt[ARP].op == 1:
                src_mac = pkt[ARP].hwsrc
                src_ip = pkt[ARP].psrc
                self.arp_data[src_mac].append(now)
                self.arp_data[src_mac] = [ts for ts in self.arp_data[src_mac] if now - ts < self.time_window]
                logging.info(f"ARP Request from MAC: {src_mac} resolved to IP: {src_ip}")
                if len(self.arp_data[src_mac]) >= self.arp_threshold:
                    logging.warning(f"Possible ARP Sweep from MAC: {src_mac} (IP: {src_ip})")
                    self.arp_data[src_mac].clear()
        except Exception as e:
            logging.error(f"Error processing ARP packet: {e}")

    def _check_icmpv6(self, pkt):
        now = datetime.now()
        if pkt.haslayer(ICMPv6EchoRequest):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            if dst_ip == self.local_ip:
                self.icmp_data[src_ip].append(now)
                self.icmp_data[src_ip] = [ts for ts in self.icmp_data[src_ip] if now - ts < self.time_window]
                if len(self.icmp_data[src_ip]) >= self.icmp_threshold:
                    logging.warning(f"ICMPv6 Echo Sweep detected from {src_ip}")
                    self.icmp_data[src_ip].clear()

    def start(self):
        try:
            self.sniffer = AsyncSniffer(filter="ip or ip6 or arp", prn=self.detect_scan, iface=self.iface, store=0)
            self.sniffer.start()
            logging.info(f"Started monitoring on {self.local_ip} (interface: {self.iface or 'all interfaces'})")
        except Exception as e:
            logging.error(f"[FATAL] Sniffing failed: {e}")

    def stop(self):
        if self.sniffer:
            self.sniffer.stop()
            logging.info("Sniffer stopped.")


def scan_port(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def list_open_ports(ip, port_range=(1, 1024), timeout=0.3, max_workers=100):
    logging.info(f"Scanning for open TCP ports on {ip} (ports {port_range[0]}–{port_range[1]})...")
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

# GUI-based Application Class
class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.monitor = None
        self.sniff_thread = None
        self.tray_icon = None

        root.title("Scan Guard Dog  Beta")
        root.geometry("950x740")
        root.configure(bg="#2e2e2e")


        # Style setup
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TButton", background="#444", foreground="#fff")
        style.configure("TCombobox", fieldbackground="#333", background="#444", foreground="#fff")

        # Interface selection
        self.iface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(root, textvariable=self.iface_var, values=get_if_list())
        self.interface_combo.set("Select Interface (or leave blank)")
        self.interface_combo.pack(fill='x', padx=10, pady=5)

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

        # Equal weight for all three columns
        for i in range(3):
            self.button_frame.grid_columnconfigure(i, weight=1)


# Second row buttons (formatted like top row)
        self.tray_button = ttk.Button(self.button_frame, text="Minimize to Tray", command=self.minimize_to_tray)
        self.tray_button.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        self.copy_button = ttk.Button(self.button_frame, text="Copy Logs to Clipboard", command=self.copy_logs)
        self.copy_button.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        self.clear_button = ttk.Button(self.button_frame, text="Clear Console", command=self.clear_console)
        self.clear_button.grid(row=1, column=2, padx=5, pady=5, sticky="ew")

        # Spacer
        tk.Frame(root, height=5, bg="#2e2e2e").pack(fill='x')

        # Alert counter
        self.alert_label = tk.Label(root, text="Alerts: 0", bg="#2e2e2e", fg="white")
        self.alert_label.pack(pady=5)

        # Log display
        self.log_display = scrolledtext.ScrolledText(
            root, state='disabled', height=20, bg="#1e1e1e",
            fg="#00ff00", insertbackground="white"
        )
        self.log_display.pack(fill='both', expand=True, padx=10, pady=10)

        # Tray icon handler on window close
        self.root.protocol("WM_DELETE_WINDOW", self.minimize_to_tray)

        # Start log update loop
        self.update_log()

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

    def clear_console(self):
        global alert_count
        alert_count = 0
        self.alert_label.config(text=f"Alerts: {alert_count}")
        self.log_display.configure(state='normal')
        self.log_display.delete("1.0", tk.END)
        self.log_display.configure(state='disabled')

    def create_tray_icon(self):
        image = self.create_image()
        self.tray_icon = pystray.Icon("Scan Guard Dog ", image, "Scan Guard Dog ", menu=pystray.Menu(
            pystray.MenuItem("Restore", self.show_window),
            pystray.MenuItem("Exit", self.exit_app)
        ))
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

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
        iface = self.iface_var.get() if 'Select' not in self.iface_var.get() else None
        self.monitor = NetworkMonitor(iface=iface)
        self.sniff_thread = threading.Thread(target=self.monitor.start, daemon=True)
        self.sniff_thread.start()
        logging.info("Monitoring started.")
        if self.tray_icon:
            self.tray_icon.icon = self.create_image("green")

    def stop_monitoring(self):
        if self.monitor:
            self.monitor.stop()
        logging.info("Monitoring stopped. Thank you for using Scan Guard.")
        self.copy_button.config(state="normal")  # Enable copy button

    def scan_ports(self):
        ip = self.monitor.local_ip if self.monitor else NetworkMonitor().get_local_ip()
        threading.Thread(target=list_open_ports, args=(ip,), daemon=True).start()

    def update_alert_label(self):
        self.alert_label.config(text=f"Alerts: {alert_count}")
        if alert_count > 0 and self.tray_icon:
            self.tray_icon.icon = self.create_image("yellow")

    def update_log(self):
        try:
            while True:
                msg = log_queue.get_nowait()
                self.log_display.configure(state='normal')
                self.log_display.insert(tk.END, msg + '\n')
                self.log_display.configure(state='disabled')
                self.log_display.yview(tk.END)
                self.update_alert_label()
        except Empty:
            pass
        finally:
            self.log_display.after(1000, self.update_log)

# Launch application
if __name__ == "__main__":
    import signal
    import sys
    import atexit

    root = tk.Tk()
    app = NetworkMonitorApp(root)

    def cleanup():
        if app.monitor:
            app.monitor.stop()
        logging.info("Application exiting: Sniffer stopped.")

    # Register cleanup for normal exits
    atexit.register(cleanup)

    # Register signal handlers for SIGINT (Ctrl+C) and SIGTERM
    signal.signal(signal.SIGINT, lambda signum, frame: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))

    try:
        root.mainloop()
    finally:
        cleanup()
