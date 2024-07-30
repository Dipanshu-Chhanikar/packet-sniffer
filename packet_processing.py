import threading
import time
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, ARP, ICMP
from filters import get_filter_string
import tkinter as tk
from anomaly_detection import AnomalyDetector  # Import the anomaly detector

class PacketProcessing:
    def __init__(self, gui):
        self.gui = gui
        self.sniffing = False
        self.packet_count = 0
        self.data_rate = 0
        self.error_count = 0
        self.packet_sizes = []
        self.timestamps = []
        self.packet_summary_map = {}
        self.anomaly_detector = AnomalyDetector(threshold=2.0)  # Initialize the anomaly detector

    def start_sniffing(self):
        self.sniffing = True
        self.packet_count = 0
        self.data_rate = 0
        self.error_count = 0
        self.packet_sizes = []
        self.timestamps = []
        self.gui.start_button.config(state=tk.DISABLED)
        self.gui.stop_button.config(state=tk.NORMAL)
        self.gui.status_label.config(text="Status: Sniffing...")
        
        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.gui.start_button.config(state=tk.NORMAL)
        self.gui.stop_button.config(state=tk.DISABLED)
        self.gui.status_label.config(text="Status: Stopped")

    def sniff_packets(self):
        if not self.gui.interface or self.gui.interface == r'\Device\NPF_Loopback':
            self.gui.log_message("Invalid or Loopback interface selected.")
            self.stop_sniffing()
            return

        filter_option = self.gui.filter_var.get()
        filter_str = get_filter_string(filter_option)
        try:
            sniff(iface=self.gui.interface, prn=self.packet_callback, store=0, filter=filter_str, stop_filter=lambda x: not self.sniffing)
        except OSError as e:
            self.gui.log_message(f"Error opening adapter: {e}")
            self.stop_sniffing()

    def apply_custom_filter(self, custom_filter):
        self.custom_filter = custom_filter
        self.stop_sniffing()
        self.start_sniffing()

    def search_logs(self, search_text):
        if search_text:
            self.gui.log_area.config(state=tk.NORMAL)
            self.gui.log_area.tag_remove('highlight', '1.0', tk.END)
            index = '1.0'
            while True:
                index = self.gui.log_area.search(search_text, index, nocase=1, stopindex=tk.END)
                if not index:
                    break
                last_index = f"{index}+{len(search_text)}c"
                self.gui.log_area.tag_add('highlight', index, last_index)
                index = last_index
            self.gui.log_area.tag_config('highlight', background='yellow')
            self.gui.log_area.config(state=tk.DISABLED)

    def packet_callback(self, packet):
        if self.sniffing:
            self.packet_count += 1
            if packet.haslayer(Raw):
                packet_size = len(packet[Raw].load)
                self.packet_sizes.append(packet_size)
                self.timestamps.append(time.time())
                
                # Detect anomalies
                anomaly_message = self.anomaly_detector.process_packet(packet_size)
                if anomaly_message:
                    self.gui.log_message(anomaly_message)

            log_message = self.get_packet_summary(packet)
            self.packet_summary_map[log_message] = packet  
            self.gui.root.after(0, self.gui.log_message, log_message)
            self.gui.root.after(0, self.gui.show_packet_details, packet)

            self.data_rate = sum(self.packet_sizes[-10:]) / 10 if self.packet_sizes else 0
            self.gui.root.after(0, self.update_traffic_stats)

    def update_traffic_stats(self):
        self.gui.packet_count_label.config(text=f"Packet Count: {self.packet_count}")
        self.gui.data_rate_label.config(text=f"Data Rate: {self.data_rate:.2f} B/s")
        self.gui.error_count_label.config(text=f"Error Count: {self.error_count}")

    def get_packet_summary(self, packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            if packet.haslayer(TCP):
                proto = "TCP"
            elif packet.haslayer(UDP):
                proto = "UDP"
            return f"{ip_src} -> {ip_dst} [{proto}]"
        return "Unknown packet"

    def decode_packet(self, packet):
        details = []
        if packet.haslayer(IP):
            details.append(f"Source IP: {packet[IP].src}")
            details.append(f"Destination IP: {packet[IP].dst}")
            details.append(f"Protocol: {packet[IP].proto}")
        if packet.haslayer(TCP):
            details.append(f"Source Port: {packet[TCP].sport}")
            details.append(f"Destination Port: {packet[TCP].dport}")
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode(errors='ignore')
                    if payload.startswith("GET") or payload.startswith("POST"):
                        details.append(f"HTTP Payload: {payload}")
                except UnicodeDecodeError:
                    pass
        if packet.haslayer(UDP):
            details.append(f"Source Port: {packet[UDP].sport}")
            details.append(f"Destination Port: {packet[UDP].dport}")
            if packet.haslayer(DNS):
                dns = packet[DNS]
                if dns.qd:
                    details.append(f"DNS Query: {dns.qd.qname.decode(errors='ignore')}")
                else:
                    details.append("DNS Query: No query section")
        if packet.haslayer(ARP):
            arp = packet[ARP]
            details.append(f"ARP Operation: {'Request' if arp.op == 1 else 'Reply'}")
            details.append(f"ARP Source MAC: {arp.hwsrc}")
            details.append(f"ARP Target MAC: {arp.hwdst}")
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            details.append(f"ICMP Type: {icmp.type}")
            details.append(f"ICMP Code: {icmp.code}")
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            details.append(f"Payload: {payload}")
        return "\n".join(details)

    def update_graph(self, ax):
        ax.clear()
        if self.timestamps and self.packet_sizes:
            ax.plot(self.timestamps, self.packet_sizes, label='Packet Size')
            ax.set_xlabel('Time')
            ax.set_ylabel('Packet Size (bytes)')
            ax.set_title('Network Traffic')
            ax.legend()
        self.gui.canvas.draw()

    def get_packet_by_summary(self, summary):
        return self.packet_summary_map.get(summary)
