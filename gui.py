import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP
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

        self.log_area = tk.Text(self.root, state=tk.DISABLED, width=80, height=20)
        self.log_area.pack(pady=10)

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
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                proto = packet[IP].proto
                if packet.haslayer(TCP):
                    proto = "TCP"
                elif packet.haslayer(UDP):
                    proto = "UDP"
                log_message = f"Packet from {ip_src} to {ip_dst} | Protocol: {proto}"
                self.log_message(log_message)

    def log_message(self, message):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.yview(tk.END)
        self.log_area.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
