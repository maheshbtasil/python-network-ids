
TCP Flood and Port Scan Detector
--------------------------------

Author: Mahesh Babu Tasil
Course: Network Protocols and Security
Semester: Spring 2025

Overview:
---------
This Python-based application captures TCP packets in real-time to detect SYN flood attacks and port scanning activity. 
It provides a Wireshark-style GUI for packet visualization and supports .pcap export/import, real-time filtering, 
graphing, and packet detail exploration.

Installation Instructions:
--------------------------
1. Install Python 3.9 or higher
2. Install the required Python packages:
   pip install scapy PyQt5 pyqtgraph
3. Install Npcap (required for Windows packet capture):
   https://npcap.com/#download

Running the Application:
------------------------
To run the tool:
   python wireshark_style_detector_with_pcap.py

Features:
---------
- Real-time TCP packet capture across all interfaces
- SYN flood and port scan detection with customizable thresholds
- Wireshark-style GUI with:
  - Filter by flag (SYN/ACK/RST/All)
  - Filter by source IP
  - Graph packets/sec in real-time
  - Load .pcap file for offline analysis
  - Export captured packets to .pcap
  - Row color-coding based on TCP flags
  - Full TCP/IP packet detail viewer
- Tooltips on table headers explain each column (e.g., Destination IP shows as 'Destination Internet Protocol')
- Reset layout button to quickly clear filters and restore the full packet view

Testing & Simulation (Optional Tools):
--------------------------------------
- Use Nmap to simulate a port scan:
  nmap -p 20-80 <target_ip>
- Use hping3 to simulate a SYN flood (via WSL or Linux):
  hping3 --flood -S -p 80 <target_ip>

Dependencies:
-------------
- Python 3.9+
- scapy
- pyqt5
- pyqtgraph
- npcap (for Windows)

Known Issues:
-------------
- On some systems, stopping Scapy capture may delay or hang due to threading.
- Large .pcap files may load slowly depending on system performance.

References:
-----------
- Scapy Documentation: https://scapy.readthedocs.io
- Wireshark User Guide: https://www.wireshark.org/docs/


License:
--------
This project is for educational use only. All dependencies follow their respective licenses.
