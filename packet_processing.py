import threading
import time
from scapy.all import sniff
from filters import get_filter_string
import tkinter as tk
from anomaly_detection import AnomalyDetector

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
        self.anomaly_detector = AnomalyDetector(threshold=2.0)

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
        sniff(iface=self.gui.interface, prn=self.process_packet, stop_filter=lambda x: not self.sniffing, filter=filter_str)

    def process_packet(self, packet):
        self.packet_count += 1
        self.packet_sizes.append(len(packet))
        self.timestamps.append(time.time())
        self.data_rate = self.packet_sizes[-1] / (self.timestamps[-1] - self.timestamps[0] + 1)

        summary = packet.summary()
        self.packet_summary_map[summary] = packet
        self.gui.log_message(summary)
        self.gui.packet_count_label.config(text=f"Packet Count: {self.packet_count}")
        self.gui.data_rate_label.config(text=f"Data Rate: {self.data_rate:.2f} B/s")

        is_anomalous = self.anomaly_detector.is_anomalous_packet(packet)
        if is_anomalous:
            self.gui.log_message(f"ALERT: Anomalous packet detected! {summary}")

    def apply_custom_filter(self, custom_filter):
        self.stop_sniffing()
        self.sniffing = True
        sniff_thread = threading.Thread(target=sniff, kwargs={'iface': self.gui.interface, 'prn': self.process_packet, 'filter': custom_filter, 'stop_filter': lambda x: not self.sniffing})
        sniff_thread.start()

    def search_logs(self, search_text):
        self.gui.log_area.tag_remove("highlight", "1.0", tk.END)
        start_pos = "1.0"
        while True:
            start_pos = self.gui.log_area.search(search_text, start_pos, tk.END)
            if not start_pos:
                break
            end_pos = f"{start_pos}+{len(search_text)}c"
            self.gui.log_area.tag_add("highlight", start_pos, end_pos)
            self.gui.log_area.tag_config("highlight", background="yellow")
            start_pos = end_pos

    def decode_packet(self, packet):
        return str(packet.show(dump=True))

    def update_graph(self, ax, graph_type):
        ax.clear()
        if graph_type == "Line":
            ax.plot(self.timestamps, self.packet_sizes)
            ax.set_title("Packet Sizes over Time")
            ax.set_xlabel("Time (s)")
            ax.set_ylabel("Packet Size (bytes)")
        elif graph_type == "Bar":
            ax.bar(self.timestamps, self.packet_sizes)
            ax.set_title("Packet Sizes over Time")
            ax.set_xlabel("Time (s)")
            ax.set_ylabel("Packet Size (bytes)")
        elif graph_type == "Scatter":
            ax.scatter(self.timestamps, self.packet_sizes)
            ax.set_title("Packet Sizes over Time")
            ax.set_xlabel("Time (s)")
            ax.set_ylabel("Packet Size (bytes)")
        elif graph_type == "Histogram":
            ax.hist(self.packet_sizes, bins=30)
            ax.set_title("Packet Size Distribution")
            ax.set_xlabel("Packet Size (bytes)")
            ax.set_ylabel("Frequency")
        elif graph_type == "Boxplot":
            ax.boxplot(self.packet_sizes)
            ax.set_title("Packet Size Boxplot")
            ax.set_ylabel("Packet Size (bytes)")
        elif graph_type == "Pie":
            sizes = [sum(self.packet_sizes) / len(self.packet_sizes)] * len(self.packet_sizes)
            labels = [f"Packet {i+1}" for i in range(len(self.packet_sizes))]
            ax.pie(sizes, labels=labels, autopct='%1.1f%%')
            ax.set_title("Packet Size Distribution")
        ax.figure.canvas.draw()

    def get_packet_by_summary(self, summary):
        return self.packet_summary_map.get(summary, None)
