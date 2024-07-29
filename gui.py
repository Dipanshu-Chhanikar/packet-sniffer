import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
import threading

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Packet Sniffer")
        
        self.sniffing = False

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

    def start_sniffing(self):
        self.sniffing = True
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
        filter_option = self.filter_var.get()
        filter_str = self.get_filter_string(filter_option)
        sniff(prn=self.packet_callback, store=0, filter=filter_str, stop_filter=lambda x: not self.sniffing)

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

    def packet_callback(self, packet):
        if self.sniffing:
            log_message = self.get_packet_summary(packet)
            self.log_message(log_message)
            self.show_packet_details(packet)

    def get_packet_summary(self, packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            if packet.haslayer(TCP):
                proto = "TCP"
            elif packet.haslayer(UDP):
                proto = "UDP"
            return f"Packet from {ip_src} to {ip_dst} | Protocol: {proto}"
        return "Unknown packet"

    def log_message(self, message):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.yview(tk.END)
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
                payload = packet[Raw].load.decode(errors='ignore')
                if packet.haslayer(HTTPRequest):
                    details.append(f"HTTP Request:\n  {payload}\n")
                elif packet.haslayer(HTTPResponse):
                    details.append(f"HTTP Response:\n  {payload}\n")
                elif "STARTTLS" in payload:
                    details.append(f"SMTP (STARTTLS):\n  {payload}\n")
                elif "EHLO" in payload or "HELO" in payload:
                    details.append(f"SMTP (EHLO/HELO):\n  {payload}\n")
                else:
                    details.append(f"TCP Raw Data:\n  {payload}\n")

        if packet.haslayer(UDP):
            details.append(f"UDP Layer:\n  Source Port: {packet[UDP].sport}\n  Destination Port: {packet[UDP].dport}\n  Length: {packet[UDP].len}\n  Checksum: {packet[UDP].chksum}\n")

            if packet.haslayer(DNS):
                if packet.getlayer(DNS).qr == 0:  # DNS query
                    details.append(f"DNS Query:\n  ID: {packet[DNS].id}\n  Questions: {packet[DNS].qdcount}\n")
                    if packet.haslayer(DNSQR):
                        details.append(f"  Query Name: {packet[DNSQR].qname.decode(errors='ignore')}\n")
                elif packet.getlayer(DNS).qr == 1:  # DNS response
                    details.append(f"DNS Response:\n  ID: {packet[DNS].id}\n  Answers: {packet[DNS].ancount}\n")
                    if packet.haslayer(DNSRR):
                        details.append(f"  Answer Name: {packet[DNSRR].rrname.decode(errors='ignore')}\n  Answer Address: {packet[DNSRR].rdata}\n")

        if packet.haslayer(Raw) and not packet.haslayer(TCP):
            details.append(f"Raw Data:\n  {packet[Raw].load}\n")

        return "\n".join(details)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
