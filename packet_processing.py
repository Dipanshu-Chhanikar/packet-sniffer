import threading
import time
import psutil  
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, ARP, ICMP
from filters import get_filter_string
import tkinter as tk
from anomaly_detection import AnomalyDetector
from collections import deque  
import logging

logging.basicConfig(filename='packet_sniffer.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class PacketProcessing:
    def __init__(self, gui):
        self.gui = gui
        self.sniffing = False
        self.packet_count = 0
        self.data_rate = 0
        self.error_count = 0
        self.packet_sizes = deque(maxlen=1000)  
        self.timestamps = deque(maxlen=1000)  
        self.packet_summary_map = {}
        self.anomaly_detector = AnomalyDetector(threshold=2.0)
        self.resource_monitoring_interval = 5   

    def start_sniffing(self):
        try:
            self.sniffing = True
            self.packet_count = 0
            self.data_rate = 0
            self.error_count = 0
            self.packet_sizes.clear()
            self.timestamps.clear()
            self.gui.start_button.config(state=tk.DISABLED)
            self.gui.stop_button.config(state=tk.NORMAL)
            self.gui.status_label.config(text="Status: Sniffing...")
            
            sniff_thread = threading.Thread(target=self.sniff_packets)
            sniff_thread.start()
            
            resource_monitoring_thread = threading.Thread(target=self.monitor_resources)
            resource_monitoring_thread.start()

        except Exception as e:
            logging.error(f"Error starting sniffing: {e}")
            self.gui.status_label.config(text="Status: Error starting sniffing.")
            self.stop_sniffing()

    def stop_sniffing(self):
        try:
            self.sniffing = False
            self.gui.start_button.config(state=tk.NORMAL)
            self.gui.stop_button.config(state=tk.DISABLED)
            self.gui.status_label.config(text="Status: Stopped")

        except Exception as e:
            logging.error(f"Error stopping sniffing: {e}")
            self.gui.status_label.config(text="Status: Error stopping sniffing.")

    def sniff_packets(self):
        try:
            if not self.gui.interface or self.gui.interface == r'\Device\NPF_Loopback':
                self.gui.log_message("Invalid or Loopback interface selected.")
                self.stop_sniffing()
                return

            filter_option = self.gui.filter_var.get()
            filter_str = get_filter_string(filter_option)
            sniff(iface=self.gui.interface, prn=self.process_packet, stop_filter=lambda x: not self.sniffing, filter=filter_str)

        except Exception as e:
            logging.error(f"Error during packet sniffing: {e}")
            self.gui.status_label.config(text="Status: Error during packet sniffing.")
            self.stop_sniffing()

    def process_packet(self, packet):
        try:
            self.packet_count += 1
            current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            self.packet_sizes.append(len(packet))
            self.timestamps.append(time.time())

            if len(self.timestamps) > 1:
                self.data_rate = self.packet_sizes[-1] / (self.timestamps[-1] - self.timestamps[0])
            else:
                self.data_rate = 0

            summary = packet.summary()
            self.packet_summary_map[summary] = packet
            self.gui.log_message(summary)
            self.gui.packet_count_label.config(text=f"Packet Count: {self.packet_count}")
            self.gui.data_rate_label.config(text=f"Data Rate: {self.data_rate:.2f} B/s")

            is_anomalous = self.anomaly_detector.is_anomalous_packet(packet)
            if is_anomalous:
                anomaly_message = f"ALERT: Anomalous packet detected! {summary} at {current_time}"
                self.gui.log_anomaly(anomaly_message)
                self.gui.log_message(anomaly_message)

        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            self.error_count += 1
            self.gui.error_count_label.config(text=f"Error Count: {self.error_count}")

    def apply_custom_filter(self, custom_filter):
        try:
            self.stop_sniffing()
            self.sniffing = True
            sniff_thread = threading.Thread(target=sniff, kwargs={'iface': self.gui.interface, 'prn': self.process_packet, 'filter': custom_filter, 'stop_filter': lambda x: not self.sniffing})
            sniff_thread.start()

        except Exception as e:
            logging.error(f"Error applying custom filter: {e}")
            self.gui.status_label.config(text="Status: Error applying custom filter.")
            self.stop_sniffing()

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
        packet_sizes_list = list(self.packet_sizes)  # Convert deque to list

        if graph_type == "Line":
            ax.plot(self.timestamps, packet_sizes_list)
        elif graph_type == "Bar":
            ax.bar(self.timestamps, packet_sizes_list)
        elif graph_type == "Scatter":
            ax.scatter(self.timestamps, packet_sizes_list)
        elif graph_type == "Histogram":
            ax.hist(packet_sizes_list, bins=30)
        elif graph_type == "Boxplot":
            ax.boxplot(packet_sizes_list)
        elif graph_type == "Pie":
            if len(packet_sizes_list) > 0:
                sizes = [sum(packet_sizes_list[i:i+10]) for i in range(0, len(packet_sizes_list), 10)]
                ax.pie(sizes, labels=[f'Chunk {i}' for i in range(len(sizes))], autopct='%1.1f%%')

        ax.set_title(f"Packet Sizes - {graph_type}")
        ax.set_xlabel("Time (s)" if graph_type not in ["Histogram", "Boxplot", "Pie"] else "")
        ax.set_ylabel("Packet Size (bytes)" if graph_type not in ["Histogram", "Boxplot", "Pie"] else "")


    def get_packet_by_summary(self, summary):
        return self.packet_summary_map.get(summary, None)

    def monitor_resources(self):
        try:
            while self.sniffing:
                cpu_usage = psutil.cpu_percent()
                memory_info = psutil.virtual_memory()
                self.gui.log_message(f"Resource Usage - CPU: {cpu_usage}%, Memory: {memory_info.percent}%")
                time.sleep(self.resource_monitoring_interval)

        except Exception as e:
            logging.error(f"Error monitoring resources: {e}")
            self.gui.status_label.config(text="Status: Error monitoring resources.")
