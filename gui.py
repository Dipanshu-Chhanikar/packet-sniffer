import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, get_if_list
from scapy.layers.http import HTTPRequest, HTTPResponse
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import time
from collections import defaultdict

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Packet Sniffer")

        self.sniffing = False
        self.packet_count = 0
        self.data_rate = 0  # Bytes per second
        self.error_count = 0

        self.packet_sizes = []
        self.timestamps = []
        
        self.create_widgets()
        
    def create_widgets(self):
        self.control_frame = ttk.Frame(self.root)
        self.control_frame.pack(pady=10)

        self.start_button = ttk.Button(self.control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = ttk.Button(self.control_frame, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.grid(row=0, column=1, padx=5)
        self.stop_button.config(state=tk.DISABLED)

        self.filter_var = tk.StringVar()
        self.filter_var.set("ALL")

        self.filter_label = ttk.Label(self.control_frame, text="Filter:")
        self.filter_label.grid(row=0, column=2, padx=5)

        self.filter_options = ttk.Combobox(self.control_frame, textvariable=self.filter_var)
        self.filter_options['values'] = ("ALL", "HTTP", "HTTPS", "SMTP", "TCP", "UDP", "IP", "FTP")
        self.filter_options.grid(row=0, column=3, padx=5)

        self.custom_filter_var = tk.StringVar()
        self.custom_filter_var.set("")
        
        self.custom_filter_label = ttk.Label(self.control_frame, text="Custom Filter:")
        self.custom_filter_label.grid(row=0, column=4, padx=5)

        self.custom_filter_entry = ttk.Entry(self.control_frame, textvariable=self.custom_filter_var)
        self.custom_filter_entry.grid(row=0, column=5, padx=5)
        
        self.apply_filter_button = ttk.Button(self.control_frame, text="Apply Custom Filter", command=self.apply_custom_filter)
        self.apply_filter_button.grid(row=0, column=6, padx=5)

        self.search_frame = ttk.Frame(self.root)
        self.search_frame.pack(pady=10)

        self.search_label = ttk.Label(self.search_frame, text="Search:")
        self.search_label.pack(side=tk.LEFT, padx=5)

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self.search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        
        self.search_button = ttk.Button(self.search_frame, text="Search", command=self.search_logs)
        self.search_button.pack(side=tk.LEFT, padx=5)

        self.log_frame = ttk.Frame(self.root)
        self.log_frame.pack(pady=10)

        self.log_area = tk.Text(self.log_frame, state=tk.DISABLED, width=80, height=15)
        self.log_area.pack(side=tk.LEFT)

        self.log_scrollbar = ttk.Scrollbar(self.log_frame, orient="vertical", command=self.log_area.yview)
        self.log_scrollbar.pack(side=tk.RIGHT, fill="y")

        self.log_area.config(yscrollcommand=self.log_scrollbar.set)

        self.detail_frame = ttk.LabelFrame(self.root, text="Packet Details")
        self.detail_frame.pack(pady=10, fill="both", expand="yes")

        self.detail_area = tk.Text(self.detail_frame, state=tk.DISABLED, width=80, height=10)
        self.detail_area.pack()

        self.status_label = ttk.Label(self.root, text="Status: Ready")
        self.status_label.pack(pady=5)
        
        # Statistics Frame
        self.stats_frame = ttk.LabelFrame(self.root, text="Traffic Statistics")
        self.stats_frame.pack(pady=10, fill="both", expand="yes")
        
        self.packet_count_label = ttk.Label(self.stats_frame, text="Packet Count: 0")
        self.packet_count_label.pack()
        
        self.data_rate_label = ttk.Label(self.stats_frame, text="Data Rate: 0 B/s")
        self.data_rate_label.pack()
        
        self.error_count_label = ttk.Label(self.stats_frame, text="Error Count: 0")
        self.error_count_label.pack()

        # Graph Frame
        self.graph_frame = ttk.LabelFrame(self.root, text="Network Traffic")
        self.graph_frame.pack(pady=10, fill="both", expand="yes")
        
        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        self.ani = FuncAnimation(self.fig, self.update_graph, interval=1000, cache_frame_data=False)

        # Hardcoded Interface
        self.interface = "Wi-Fi"

    def start_sniffing(self):
        self.sniffing = True
        self.packet_count = 0
        self.data_rate = 0
        self.error_count = 0
        self.packet_sizes = []
        self.timestamps = []
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Sniffing...")
        
        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped")

    def sniff_packets(self):
        if not self.interface or self.interface == r'\Device\NPF_Loopback':
            self.log_message("Invalid or Loopback interface selected.")
            self.stop_sniffing()
            return

        filter_option = self.filter_var.get()
        filter_str = self.get_filter_string(filter_option)
        try:
            sniff(iface=self.interface, prn=self.packet_callback, store=0, filter=filter_str, stop_filter=lambda x: not self.sniffing)
        except OSError as e:
            self.log_message(f"Error opening adapter: {e}")
            self.stop_sniffing()

    def get_filter_string(self, option):
        if option == "HTTP":
            return "tcp port 80"
        elif option == "HTTPS":
            return "tcp port 443"
        elif option == "SMTP":
            return "tcp port 25"
        elif option == "TCP":
            return "tcp"
        elif option == "UDP":
            return "udp"
        elif option == "IP":
            return "ip"
        elif option == "FTP":
            return "tcp port 21"
        else:
            return ""

    def apply_custom_filter(self):
        self.custom_filter = self.custom_filter_var.get()
        self.stop_sniffing()
        self.start_sniffing()

    def search_logs(self):
        search_text = self.search_var.get()
        if search_text:
            self.log_area.config(state=tk.NORMAL)
            self.log_area.tag_remove('highlight', '1.0', tk.END)
            index = '1.0'
            while True:
                index = self.log_area.search(search_text, index, nocase=1, stopindex=tk.END)
                if not index:
                    break
                last_index = f"{index}+{len(search_text)}c"
                self.log_area.tag_add('highlight', index, last_index)
                index = last_index
            self.log_area.tag_config('highlight', background='yellow')
            self.log_area.config(state=tk.DISABLED)

    def packet_callback(self, packet):
        if self.sniffing:
            self.packet_count += 1
            if packet.haslayer(Raw):
                self.packet_sizes.append(len(packet[Raw].load))
                self.timestamps.append(time.time())
            
            log_message = self.get_packet_summary(packet)
            self.log_message(log_message)
            self.show_packet_details(packet)

            # Update traffic statistics
            self.data_rate = sum(self.packet_sizes[-10:]) / 10 if self.packet_sizes else 0
            self.packet_count_label.config(text=f"Packet Count: {self.packet_count}")
            self.data_rate_label.config(text=f"Data Rate: {self.data_rate:.2f} B/s")
            self.error_count_label.config(text=f"Error Count: {self.error_count}")

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

    def log_message(self, message):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.config(state=tk.DISABLED)

    def show_packet_details(self, packet):
        self.detail_area.config(state=tk.NORMAL)
        self.detail_area.delete(1.0, tk.END)
        details = self.decode_packet(packet)
        self.detail_area.insert(tk.END, details)
        self.detail_area.config(state=tk.DISABLED)

    def decode_packet(self, packet):
        details = []

        if packet.haslayer(IP):
            details.append(f"IP Layer:\n  Source: {packet[IP].src}\n  Destination: {packet[IP].dst}\n  Version: {packet[IP].version}\n  Header Length: {packet[IP].ihl}\n  TTL: {packet[IP].ttl}\n  Protocol: {packet[IP].proto}\n  Checksum: {packet[IP].chksum}\n")

        if packet.haslayer(TCP):
            details.append(f"TCP Layer:\n  Source Port: {packet[TCP].sport}\n  Destination Port: {packet[TCP].dport}\n  Sequence Number: {packet[TCP].seq}\n  Acknowledgment Number: {packet[TCP].ack}\n  Data Offset: {packet[TCP].dataofs}\n  Reserved: {packet[TCP].reserved}\n  Flags: {packet[TCP].flags}\n  Window: {packet[TCP].window}\n  Checksum: {packet[TCP].chksum}\n  Urgent Pointer: {packet[TCP].urgptr}\n")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                details.append(self.parse_http_payload(payload.decode(errors='ignore')))
            else:
                details.append(self.parse_raw_payload(payload))

        if packet.haslayer(UDP):
            details.append(f"UDP Layer:\n  Source Port: {packet[UDP].sport}\n  Destination Port: {packet[UDP].dport}\n  Length: {packet[UDP].len}\n  Checksum: {packet[UDP].chksum}\n")
        
        if packet.haslayer(Raw) and packet.haslayer(DNS):
            details.append(self.parse_dns_payload(packet[Raw].load))

        if packet.haslayer(Raw) and not packet.haslayer(TCP):
            details.append(f"Raw Data:\n  {self.parse_raw_payload(packet[Raw].load)}\n")

        return "\n".join(details)

    def parse_http_payload(self, payload):
        try:
            headers, body = payload.split(b'\r\n\r\n', 1)
            header_lines = headers.decode(errors='ignore').split('\r\n')
            parsed_headers = '\n'.join(header_lines)
            first_line = header_lines[0]
            return f"HTTP Header:\n{parsed_headers}\n\nHTTP Body:\n{body.decode(errors='ignore')}"
        except ValueError:
            return f"HTTP Data:\n{payload.decode(errors='ignore')}"

    def parse_dns_payload(self, payload):
        dns_data = []
        try:
            dns_packet = DNS(payload)
            if dns_packet.qr == 0:
                dns_data.append(f"Query ID: {dns_packet.id}")
                dns_data.append(f"Questions: {dns_packet.qdcount}")
                for query in dns_packet.qd:
                    dns_data.append(f"  Query Name: {query.qname.decode(errors='ignore')}")
            elif dns_packet.qr == 1:
                dns_data.append(f"Response ID: {dns_packet.id}")
                dns_data.append(f"Answers: {dns_packet.ancount}")
                for answer in dns_packet.an:
                    dns_data.append(f"  Answer Name: {answer.rrname.decode(errors='ignore')}")
                    dns_data.append(f"  Answer Address: {answer.rdata}")
            return '\n'.join(dns_data)
        except Exception as e:
            return f"DNS Data:\n{payload.decode(errors='ignore')}\nError: {str(e)}"

    def parse_raw_payload(self, payload):
        try:
            hex_data = ' '.join(f'{b:02x}' for b in payload)
            ascii_data = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload)
            parsed_data = []
            parsed_data.append(f"Hex Data:\n{hex_data}")
            parsed_data.append(f"ASCII Data:\n{ascii_data}")
            return '\n'.join(parsed_data)
        except Exception as e:
            return f"Raw Data:\n{payload.decode(errors='ignore')}\nError: {str(e)}"

    def update_graph(self, frame):
        self.ax.clear()
        if self.timestamps and self.packet_sizes:
            self.ax.plot(self.timestamps, self.packet_sizes, label='Packet Size')
            self.ax.set_xlabel('Time')
            self.ax.set_ylabel('Packet Size (bytes)')
            self.ax.set_title('Network Traffic')
            self.ax.legend()
        self.canvas.draw()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
