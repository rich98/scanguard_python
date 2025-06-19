# Scan Guard Dog For Windows

Current Version.0.6.5

New Classes suspicious_port_detector_v1.py, help_file_viewer_v1.py

# Whats new 0.5.9 (0.5.9.2 minor bug fix in treeview)

New class Whitelisting for know good IP's v1.
Light \ Dark mode improvements. 
Improvements for flood logic (not finished).
Update to flood protection (0.5.9.1)
Bug fix IDS function now logs once - not twice (0.5.9.2)

![image](https://github.com/user-attachments/assets/cd339546-038b-4e55-9cb1-1eb3f75d0eb3)

# Whats new 0.5.6

First class to be split from main application
Bug fix in kill switch and Stop monitor could cause the appliction to hang
To use exstract the zip file, both files need to be in the same directory
Flood Protection feature
Adjustments to active counters
The orignal alert counter retired

![image](https://github.com/user-attachments/assets/cf14741e-eb1e-47a7-a82e-78aed8443cd9)


# Whsts new? 0.4.28
# Syslog
- Syslog toggle switch updateing the classes and methods (see the ARP warings being logged on a remote server.
  At the moment the ip address is hardcoded but will implent a persistent settings (.ini file) in time For now its a MVP
  The fuction is off by default
![image](https://github.com/user-attachments/assets/ef536594-b950-4d17-9532-8e9c7383352d)

![image](https://github.com/user-attachments/assets/132369b4-65b4-413c-9795-79268f6ba7e1)

✨ GUI Enhancements & Abnormality Table Integration

- Added Treeview-based abnormality grid with auto-scroll
- Integrated vertical scrollbar for overflow control
- Injected real-time IDS data via `add_abnormality_to_grid()`
- Highlighted abnormal log messages in purple for quick triage
- Improved update_log() pattern detection with structured tags
  
# Building "Scan Guard Pro Beta": A GUI-Based Passive Network Threat Monitor in Python
In today’s increasingly complex and security-conscious IT landscape, having visibility into network reconnaissance activities is more critical than ever. Attackers often begin their campaigns with simple scans to identify open ports, active hosts, and vulnerabilities. Recognizing this foundational threat vector, I developed Scan Guard Pro Beta, a GUI-driven, cross-platform passive monitoring tool written entirely in Python. Leveraging the power of Scapy, the flexibility of Tkinter, and the system tray integration capabilities of pystray, this utility is intended for network professionals who value clarity, control, and a strong adherence to best practices.

Scan Guard Pro Beta provides real-time alerts, a visual display of scan activity, and seamless system integration without relying on external dependencies or heavyweight security suites. In keeping with traditional software design values, the tool is built to be understandable, maintainable, and extendable.

![image](https://github.com/user-attachments/assets/68cd0bef-81f7-4f47-844c-c417b473fb8e)

# What Does It Do?
Scan Guard Pro Beta focuses on detecting several common reconnaissance and enumeration techniques that are frequently employed in penetration testing and by malicious actors. By identifying these behaviors early in the intrusion chain, the tool enables defenders to respond before attackers escalate their access or move laterally through the network.

TCP SYN Port Scans — attempts to discover open TCP ports via half-open handshake packets. This technique is favored due to its speed and ability to avoid full connections, making it stealthier than traditional scans. Scan Guard Pro Beta detects these SYN packets and analyzes their distribution over time to determine suspicious patterns.

![image](https://github.com/user-attachments/assets/bef3eb12-13e9-4e66-8c24-ff43552cb9cc)


UDP Port Probing — used to elicit responses from open UDP services. Although harder to detect due to the lack of handshake, Scan Guard Pro Beta watches for a burst of UDP packets to multiple destination ports, a strong indicator of probing behavior intended to map services or vulnerabilities.

ARP Sweeps — often a precursor to a man-in-the-middle attack or lateral movement. Attackers use ARP sweeps to discover active devices on a local subnet. By observing rapid ARP requests from a single source, the software identifies potential enumeration attempts that could precede spoofing or poisoning attacks.

![image](https://github.com/user-attachments/assets/9528d4e3-ee09-4cda-8ad2-05f5d3ec83f5)


ICMP Requests — classic ping sweeps for identifying live hosts on both IPv4 and IPv6 networks. These techniques form the basis of many discovery tools and can also indicate automated scanning tools attempting to map the network topology. (Support for IPv6 coming soon

In each case, Scan Guard Pro Beta not only recognizes the behavior but contextualizes it within a sliding time window to reduce false positives. Once suspicious activity is detected, the software immediately logs the event to a persistent file, displays the alert in the GUI for the user’s attention, and changes the system tray icon to a distinct warning color. This multimodal alerting mechanism ensures users are notified both actively and passively, allowing for timely investigation without overwhelming them with data or requiring constant visual attention. This thoughtful design helps security teams stay informed while preserving workflow efficiency and clarity.

🧰 Technologies Used
The software combines several robust and time-tested Python libraries, each carefully selected to ensure performance, maintainability, and cross-platform compatibility. These components work in tandem to offer a seamless user experience while handling complex background tasks inherent to network monitoring:

Python 3 — Serving as the foundation of the application, Python 3 is widely respected in cybersecurity for its ease of use, readability, and immense library ecosystem. Its versatility enables rapid development, simplifies prototyping, and allows integration with other tools and APIs when needed.

Scapy — This indispensable library provides powerful capabilities for packet sniffing, crafting, and dissection. It allows the tool to operate at a lower layer of the OSI model, ensuring fine-grained visibility into traffic patterns and supporting nuanced detection logic for reconnaissance techniques.

Tkinter — Included in the standard Python distribution, Tkinter provides a no-frills yet effective way to build desktop GUI applications. It is platform-independent, reliable, and responsive, and offers enough flexibility for a professional layout without requiring third-party dependencies.

pystray + Pillow (PIL) — This combination manages the tray icon functionality and visual status feedback. It allows the application to minimize into the system tray while dynamically changing the tray icon's color depending on alert status, offering a subtle but effective alerting mechanism for ongoing passive monitoring.

Threading and AsyncSniffer — These tools underpin the application’s responsiveness. Threading separates the UI from the packet capture process, preventing UI freezes during high-traffic periods. AsyncSniffer ensures packets are collected asynchronously, making the detection pipeline both efficient and scalable.

Logging + RotatingFileHandler — Robust logging is vital for auditability and diagnostics. Using Python's built-in logging framework with rotation capability ensures that logs remain manageable over time. Historical data is preserved across sessions while preventing disk overuse.

These technologies were deliberately selected for their proven reliability, simplicity of integration, and strong community support. Together, they form a solid backbone that enables Scan Guard Pro Beta to deliver consistent performance on major operating systems including Linux, macOS, and Windows, while remaining easy to maintain and extend by any Python-literate developer or security professional.

🖥️ User Interface
The interface of Scan Guard Pro Beta is intentionally kept clean and uncluttered, emphasizing function over flair. Its design prioritizes ease of use, quick access to critical controls, and real-time situational awareness. Each element of the GUI has been carefully curated to provide essential information and control without overwhelming the user, making the tool approachable for both experienced professionals and newcomers alike. It features:

Interface Selection Dropdown: Select your desired network adapter or leave it blank to monitor all. The dropdown dynamically populates with available interfaces, enabling the user to focus monitoring on a specific network segment when necessary.

Control Buttons: Start and stop network sniffing sessions easily with responsive buttons designed for clarity and accessibility. This immediate control allows administrators to pause scanning for diagnostics or change settings without exiting the application.

Port Scan Tool: Executes a multithreaded TCP scan on the host to identify open local ports. This built-in utility is particularly useful for verifying firewall configurations, identifying unnecessary services, and conducting internal audits without relying on third-party tools.

Live Alert Counter: Instantly displays how many alerts have been generated since the last reset. This visual indicator acts as a quick reference for assessing the current threat environment and monitoring the frequency of scanning attempts over time.

Scrollable Log Window: Shows real-time monitoring activity with color-coded messages. The display highlights warnings, errors, and informational messages distinctly, ensuring that critical events stand out during high traffic or complex sessions.

System Tray Minimization: Allows the app to run in the background with a colored square in the tray indicating system state. The tray icon can be right-clicked to restore the application or exit, providing a seamless integration into desktop workflows.

System tray Icon ![image](https://github.com/user-attachments/assets/da53122f-0abe-4057-901f-ae59a7a2ead2) 
Yelloew when possible threat detected ![image](https://github.com/user-attachments/assets/cf5a949c-59fe-47ba-bd6a-5520b4a0bd7f)


When suspicious activity is identified, the tray icon color changes (e.g., from green to yellow), alerting the user passively. This ensures that administrators can remain informed without keeping the application window constantly in the foreground. Additionally, the interface design supports adaptability for future enhancements, such as graphical dashboards or notification banners, while retaining the current balance of functionality and simplicity.

🧠 How Detection Works
At the core of Scan Guard Pro Beta is a pattern-based detection mechanism built around sliding time windows, a concept that enables the application to maintain context about packet behavior over time rather than reacting to isolated events. This time-based approach helps distinguish between normal network noise and patterns indicative of a scan or enumeration attempt.

For each supported packet type, the application maintains internal dictionaries keyed by identifiers such as source IP or MAC address. These dictionaries contain lists of timestamped records corresponding to specific network interactions, such as port access attempts or ICMP echo requests. These logs are continuously updated and purged of entries older than the configured detection window to maintain only relevant, real-time data.

TCP Port Scan Detection: The tool monitors incoming TCP SYN packets—used to initiate a TCP handshake—and records each destination port contacted by a given source. If a single IP address sends SYN packets to multiple different ports on the local machine within the sliding time window, and this count exceeds a configurable threshold, a port scan alert is generated. This helps flag common reconnaissance tools such as Nmap or masscan.

UDP Scan Detection: UDP scans are harder to detect due to the stateless nature of UDP, but the application tracks destination ports targeted by each source IP. When the number of unique UDP ports accessed by a host exceeds a defined threshold in a short span, a UDP probe is suspected and flagged.

ICMP Echo Requests: Repeated ICMP echo requests—commonly known as ping sweeps—are captured and aggregated. When a burst of such requests is observed from the same source to multiple destinations or repeated hits on the local machine, the application logs this as an attempted discovery scan.

ARP Request Monitoring: ARP requests can reveal live hosts in a subnet. A high frequency of ARP broadcasts originating from a single MAC address within a narrow time window may indicate a layer 2 sweep. The tool logs and alerts on this behavior when it crosses a sensitivity threshold.

These detection techniques are designed to strike a balance between sensitivity and specificity. False positives are minimized through adjustable thresholds and time parameters that can be tailored to the characteristics of the local environment. Additionally, each detection mechanism is encapsulated in modular functions, making them easy to enhance or replace. This architecture facilitates future upgrades, protocol support expansion, or the integration of adaptive intelligence based on evolving threat models.

✅ Security-Conscious Features
Security is central to the design of this tool, reflecting a conservative yet robust approach to maintaining system integrity during operation. Every component of Scan Guard Pro Beta has been constructed with safeguards that uphold not only performance reliability but also defensive consistency under real-world use conditions:

Privilege Validation: The tool enforces a strict requirement for elevated privileges, which is critical for accessing raw network interfaces. This ensures that unauthorized or insufficiently privileged use is gracefully denied, preventing silent failures or incomplete monitoring.

Graceful Shutdown: The application integrates signal handling and atexit routines to ensure that all background threads, especially packet sniffers, are terminated cleanly. This prevents resource locking, dangling processes, or corrupted log files that could complicate diagnostics or system restarts.

Log Management: Leveraging Python's RotatingFileHandler, Scan Guard Pro Beta keeps log sizes manageable and prevents disk space exhaustion. Logs are rolled automatically based on size thresholds, maintaining a history of activity while ensuring the system remains operational over extended periods.

Thread Safety: The software separates the packet sniffing process from GUI rendering and user input handling by using distinct threads. This isolation guarantees that heavy traffic volumes do not interfere with the application's responsiveness, preserving usability even during active scan events.

Operational Reliability: Beyond code structure, the application is designed to be left running for long durations, whether on dedicated monitoring workstations or as a background utility on general-use systems. Careful memory management and non-blocking I/O routines ensure consistent performance.

Minimal System Footprint: With no kernel modules, daemons, or background services, Scan Guard Pro Beta minimizes potential vectors for attack or system misconfiguration, making it a safe addition to any security-conscious environment.

These design principles reflect a commitment to operational trustworthiness. Whether deployed in educational settings, corporate offices, or security labs, the tool is built to remain stable, transparent, and dependable throughout extended usage cycles or under various network conditions.

🔒 Why Build This?
In the enterprise space, there are several heavyweight tools available for traffic analysis, intrusion detection, and endpoint monitoring. While these comprehensive systems are valuable in large-scale deployments, they can often be overkill for smaller operations or environments that favor minimalism and control over automation and cloud integration. In contrast, many organizations—particularly small businesses, educational institutions, security training labs, or air-gapped testbeds—require simpler, more focused solutions that do not rely on vast infrastructures or advanced configurations.

Scan Guard Pro Beta fills this critical niche by providing a security tool that is:

Easy to deploy and use, requiring minimal setup and no prior knowledge of complex IDS platforms.

Platform-agnostic, running reliably across Linux, macOS, and Windows with no proprietary dependencies.

Focused on early threat detection, particularly at the reconnaissance stage when an attacker is mapping network vulnerabilities.

Not reliant on cloud infrastructure or third-party telemetry, ensuring full user control and offline usability.

Transparent and auditable, with readable logs, simple rule logic, and open-source access.

Lightweight and portable, capable of running on legacy systems or within constrained environments such as Raspberry Pi units or minimal VM images.

This project embodies a philosophy of practical security: empower users with tools that are transparent, easy to audit, respect local control, and operate on the principle of minimal trust. It reinforces the idea that powerful network defense doesn't always require complex stacks—instead, it often begins with visibility, simplicity, and informed operators.

🏑 Future Enhancements
The roadmap for Scan Guard Pro Beta includes several practical extensions aimed at making the tool more dynamic, responsive, and suitable for broader deployment scenarios:

Email/Webhook Notifications: Integrating real-time notification systems to inform administrators or security personnel immediately when suspicious activity is detected. This can include SMTP support, Slack integration, or webhook endpoints for SIEM platforms.

User-Defined Rules: Empower users with the ability to write and manage their own detection logic, adjusting thresholds, time windows, and response triggers to match specific environments. This will make the tool more adaptable to varied security postures.

Settings Persistence: Implementing profile save/load functionality that allows users to store their interface preferences, detection thresholds, and logging configurations for reusability across sessions or deployments.

Response Actions: Introducing a basic response engine capable of triggering system-level actions such as executing a script, adding a temporary firewall rule, sending an alert to another system, or isolating a device on the network.

Improved IPv6 Support: Expanding the tool's reach into dual-stack and IPv6-only networks with deeper inspection of modern protocols and ICMPv6 behavior, ensuring parity with IPv4 monitoring.

Dashboard Visualization: A planned GUI enhancement that provides pie charts, bar graphs, and timelines summarizing traffic patterns, scan attempts, and detection history to aid in reporting and visualization.

Modular Plugin System: Laying the groundwork for community or third-party plugin development, allowing new protocols, scan types, or integrations to be added without changing the core code.

Feedback, testing suggestions, and development contributions from the community are strongly encouraged to ensure the future versions of Scan Guard Pro Beta continue to meet the practical needs of cybersecurity professionals and IT teams alike.

🚀 Try It Yourself
The tool is released under the Apache 2.0 License and designed with accessibility in mind, making it both legally permissive and technically approachable for IT professionals, educators, and hobbyists. Getting started is quick and straightforward, especially for users already familiar with basic Python workflows:

Install required dependencies using pip: pip install scapy pystray pillow. These libraries support packet parsing, tray icon management, and image handling, which are core to the application.

Ensure the script is executed with elevated privileges—either as an Administrator on Windows or using sudo on Linux/macOS—since raw packet sniffing requires root access.

Launch the application, select a network interface from the dropdown list, or allow it to use all interfaces by default. The system will begin passively monitoring immediately upon activation.

Observe the real-time logs, which reflect ongoing network activity, detected scans, and alert messages. These logs are displayed in a scrollable, color-coded window.

Minimize the application to the system tray to continue monitoring discreetly in the background. The icon's color dynamically updates to indicate the presence or absence of threats.

It is strongly recommended to first deploy the tool in a controlled lab environment before applying it to live systems. This allows users to become familiar with its behavior, validate its detection thresholds, and fine-tune its settings. Additionally, the logs generated during this phase can be invaluable for training purposes, enabling team members to better recognize common reconnaissance techniques and their network footprints. Exported logs may also serve as supplementary material for compliance documentation or incident response simulations.

If you're looking for a dependable, GUI-driven passive scanner that respects your system's integrity while offering clear insight into potentially malicious activity, Scan Guard Pro Beta is worth exploring. It stands as a reminder that traditional, minimalistic tools can remain highly effective in a modern security toolkit.

Please feel free to connect if you're interested in collaborating, suggesting features, or deploying this in a real-world scenario.

![50scan guard](https://github.com/user-attachments/assets/4749c1a2-465e-46e1-8916-e821791ca848)

# Known Issues

Code needs to be opitmized

Whois DNS

![image](https://github.com/user-attachments/assets/222d2c2d-516b-454c-8f86-be5b50b80b10)

DNS does not resolve with blank screen and error: when resolving 8.8.8.8

2025-05-25 13:38:02,066 - ERROR - Error trying to connect to socket: closing socket - [Errno 11001] getaddrinfo failed

Other IP returns information

![image](https://github.com/user-attachments/assets/047805e4-e6f8-404b-8025-d68ea00cdcf2)

Interface names are unfriendly

![image](https://github.com/user-attachments/assets/b3aacf38-41da-4e8c-b10b-ec61c89c9388)

