
import sys
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QMessageBox,
    QStatusBar, QLabel, QComboBox, QLineEdit, QTextEdit, QFileDialog
)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QColor
from scapy.all import sniff, IP, TCP, wrpcap, rdpcap
from threading import Thread
from collections import defaultdict, deque
import pyqtgraph as pg

class TCPDetectorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wireshark-Style TCP Flood and Port Scan Detector (with PCAP Import)")
        self.setGeometry(50, 50, 1400, 800)

        self.capture_active = False
        self.packet_counts = deque(maxlen=60)
        self.captured_packets = []
        self.filtered_packets = []
        self.last_alert = ""
        self.capture_start_time = None

        self.syn_packets = defaultdict(list)
        self.port_scans = defaultdict(set)
        self.SYN_FLOOD_THRESHOLD = 100
        self.PORT_SCAN_THRESHOLD = 10
        self.TIME_WINDOW = 10

        self.central_widget = QWidget()
        self.main_layout = QVBoxLayout(self.central_widget)

        filter_layout = QHBoxLayout()
        self.flag_filter = QComboBox()
        self.flag_filter.addItems(["All", "SYN", "ACK", "RST", "Alert"])
        self.ip_filter = QLineEdit()
        self.ip_filter.setPlaceholderText("Filter by Source IP")
        self.apply_filter_btn = QPushButton("Apply Filter")
        self.apply_filter_btn.clicked.connect(self.apply_filters)
        filter_layout.addWidget(QLabel("TCP Flag:"))
        filter_layout.addWidget(self.flag_filter)
        filter_layout.addWidget(QLabel("Source IP:"))
        filter_layout.addWidget(self.ip_filter)
        filter_layout.addWidget(self.apply_filter_btn)
        self.main_layout.addLayout(filter_layout)

        controls_layout = QHBoxLayout()
        self.capture_btn = QPushButton("Start Capture")
        self.capture_btn.clicked.connect(self.toggle_capture)
        self.export_btn = QPushButton("Export Packets to PCAP")
        self.export_btn.clicked.connect(self.export_packets)
        self.reset_btn = QPushButton("Reset Layout")
        self.reset_btn.clicked.connect(self.reset_layout)
        self.load_pcap_btn = QPushButton("Load PCAP File")
        self.load_pcap_btn.clicked.connect(self.load_pcap_file)
        controls_layout.addWidget(self.capture_btn)
        controls_layout.addWidget(self.export_btn)
        controls_layout.addWidget(self.reset_btn)
        controls_layout.addWidget(self.load_pcap_btn)
        self.main_layout.addLayout(controls_layout)

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(["Timestamp", "Src IP", "Src Port", "Dst IP", "Dst Port", "Flags"])
        header_tooltips = [
            "Packet capture timestamp",
            "Source Internet Protocol Address",
            "Source Port Number",
            "Destination Internet Protocol Address",
            "Destination Port Number",
            "TCP Flags (SYN, ACK, etc.)"
        ]
        for i in range(6):
            self.packet_table.horizontalHeaderItem(i).setToolTip(header_tooltips[i])
        self.packet_table.cellClicked.connect(self.show_packet_details)
        self.main_layout.addWidget(self.packet_table)

        self.detail_viewer = QTextEdit()
        self.detail_viewer.setReadOnly(True)
        self.detail_viewer.setPlaceholderText("Click on a packet row to view detailed information here...")
        self.main_layout.addWidget(self.detail_viewer)

        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground('w')
        self.plot_widget.setTitle("Packets Captured Per Second")
        self.plot_widget.setLabel('left', 'Packets/sec')
        self.plot_widget.setLabel('bottom', 'Seconds ago')
        self.packet_curve = self.plot_widget.plot(pen='b')
        self.main_layout.addWidget(self.plot_widget)

        self.setCentralWidget(self.central_widget)
        self.status = QStatusBar()
        self.setStatusBar(self.status)

        self.graph_timer = QTimer()
        self.graph_timer.timeout.connect(self.update_graph)
        self.graph_timer.start(1000)

        self.current_packet_count = 0

    def toggle_capture(self):
        if not self.capture_active:
            self.capture_active = True
            self.capture_btn.setText("Stop Capture")
            self.capture_start_time = time.time()
            self.sniff_thread = Thread(target=self.start_sniffing, daemon=True)
            self.sniff_thread.start()
        else:
            self.capture_active = False
            self.capture_btn.setText("Start Capture")

    def start_sniffing(self):
        sniff(filter="tcp", prn=self.process_packet, stop_filter=self.should_stop_capture)

    def process_packet(self, packet):
        self.current_packet_count += 1
        current_time = time.time()
        if IP in packet and TCP in packet:
            self.captured_packets.append(packet)
            self.filtered_packets.append(packet)
            self.add_packet_to_table(packet)

    def add_packet_to_table(self, packet):
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)
        values = [
            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(packet.time))),
            packet[IP].src,
            str(packet[TCP].sport),
            packet[IP].dst,
            str(packet[TCP].dport),
            str(packet[TCP].flags)
        ]
        flag = packet[TCP].flags
        color = None
        if flag == 'S':
            color = '#FFFFCC'
        elif 'R' in flag:
            color = '#FFCCCC'
        elif 'A' in flag:
            color = '#CCE5FF'
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            if color:
                item.setBackground(QColor(color))
            self.packet_table.setItem(row_position, col, item)
        self.packet_table.scrollToBottom()

    def alert_attack(self, attack_type, ip, ports=None):
        message = f"{attack_type} detected from IP: {ip}"
        if ports:
            message += f"\nPorts: {', '.join(str(p) for p in ports)}"
        self.last_alert = f"{attack_type} from {ip}"
        self.status.showMessage(f"[ALERT] {self.last_alert}")
        alert = QMessageBox()
        alert.setWindowTitle("Attack Alert!")
        alert.setText(message)
        alert.setIcon(QMessageBox.Critical)
        alert.exec_()

    def export_packets(self):
        if not self.captured_packets:
            QMessageBox.warning(self, "No Packets", "No packets captured yet to export.")
            return
        try:
            filename = f"captured_packets_{int(time.time())}.pcap"
            wrpcap(filename, self.captured_packets)
            QMessageBox.information(self, "Export Successful", f"Packets exported successfully as {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to export packets:{str(e)}")

    def should_stop_capture(self, packet):
        return not self.capture_active

    def update_graph(self):
        self.packet_counts.append(self.current_packet_count)
        self.current_packet_count = 0
        data = list(self.packet_counts)
        self.packet_curve.setData(data, pen='b')
        self.plot_widget.setXRange(0, len(data))
        self.plot_widget.setYRange(0, max(data) + 1 if data else 1)
        timer = f"{int(time.time() - self.capture_start_time)}s" if self.capture_start_time else "N/A"
        self.status.showMessage(f"Packets/sec: {data[-1] if data else 0} | Last Alert: {self.last_alert or 'None'} | Time: {timer}")

    def reset_layout(self):
        self.packet_table.setRowCount(0)
        self.packet_counts.clear()
        self.packet_curve.clear()
        self.captured_packets.clear()
        self.filtered_packets.clear()
        self.syn_packets.clear()
        self.port_scans.clear()
        self.current_packet_count = 0
        self.last_alert = ""
        self.capture_start_time = None
        self.status.showMessage("Layout reset. All data cleared.")
        self.detail_viewer.clear()

    def show_packet_details(self, row, col):
        try:
            packet = self.filtered_packets[row]
            self.detail_viewer.setText(str(packet.show(dump=True)))
        except:
            self.detail_viewer.setText("Unable to fetch details for this packet.")

    def apply_filters(self):
        flag = self.flag_filter.currentText()
        ip = self.ip_filter.text().strip()
        self.filtered_packets = []
        self.packet_table.setRowCount(0)
        for pkt in self.captured_packets:
            if not (IP in pkt and TCP in pkt):
                continue
            match_ip = ip == "" or pkt[IP].src == ip
            match_flag = (
                flag == "All" or
                (flag == "SYN" and pkt[TCP].flags == "S") or
                (flag == "ACK" and "A" in pkt[TCP].flags) or
                (flag == "RST" and "R" in pkt[TCP].flags)
            )
            if match_ip and match_flag:
                self.filtered_packets.append(pkt)
                self.add_packet_to_table(pkt)

    def load_pcap_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Open PCAP File", "", "PCAP Files (*.pcap *.cap)")
        if file_path:
            try:
                packets = rdpcap(file_path)
                self.reset_layout()
                for pkt in packets:
                    if IP in pkt and TCP in pkt:
                        self.captured_packets.append(pkt)
                        self.filtered_packets.append(pkt)
                        self.add_packet_to_table(pkt)
                self.status.showMessage(f"Loaded {len(packets)} packets from {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Load Failed", f"Could not read file:{str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TCPDetectorGUI()
    window.show()
    sys.exit(app.exec_())
