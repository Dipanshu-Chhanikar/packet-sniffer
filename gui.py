import tkinter as tk
from tkinter import ttk
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
from packet_processing import PacketProcessing
import psutil
import logging
from scapy.all import sniff

logging.basicConfig(filename='packet_sniffer.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')


class PacketSnifferGUI:
    def __init__(self, root):
        try:
            self.root = root
            self.root.title("Advanced Packet Sniffer Dashboard")
            self.packet_processing = PacketProcessing(self)
            self.create_widgets()
            self.resource_monitoring_id = None
            self.sniffing = False

        except Exception as e:
            logging.error(f"Error initializing GUI: {e}")
            self.root.destroy()

    def create_widgets(self):
        # Create main frames
        self.control_frame = ttk.LabelFrame(self.root, text="Controls")
        self.control_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.stats_frame = ttk.LabelFrame(self.root, text="Traffic Statistics")
        self.stats_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        self.graph_frame = ttk.LabelFrame(self.root, text="Network Traffic")
        self.graph_frame.grid(row=0, column=1, rowspan=2, padx=10, pady=10, sticky="nsew")

        self.log_frame = ttk.LabelFrame(self.root, text="Logs")
        self.log_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        self.detail_frame = ttk.LabelFrame(self.root, text="Packet Details")
        self.detail_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        self.resource_frame = ttk.LabelFrame(self.root, text="Resource Monitoring")
        self.resource_frame.grid(row=0, column=2, rowspan=2, padx=10, pady=10, sticky="nsew")

        # Control frame widgets
        self.start_button = ttk.Button(self.control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=5, pady=5)

        self.stop_button = ttk.Button(self.control_frame, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)
        self.stop_button.config(state=tk.DISABLED)

        self.filter_label = ttk.Label(self.control_frame, text="Filter:")
        self.filter_label.grid(row=0, column=2, padx=5, pady=5)

        self.filter_var = tk.StringVar()
        self.filter_var.set("ALL")
        self.filter_options = ttk.Combobox(self.control_frame, textvariable=self.filter_var)
        self.filter_options['values'] = ("ALL", "HTTP", "HTTPS", "SMTP", "TCP", "UDP", "IP", "FTP")
        self.filter_options.grid(row=0, column=3, padx=5, pady=5)

        self.custom_filter_label = ttk.Label(self.control_frame, text="Custom Filter:")
        self.custom_filter_label.grid(row=0, column=4, padx=5, pady=5)

        self.custom_filter_var = tk.StringVar()
        self.custom_filter_entry = ttk.Entry(self.control_frame, textvariable=self.custom_filter_var)
        self.custom_filter_entry.grid(row=0, column=5, padx=5, pady=5)

        self.apply_filter_button = ttk.Button(self.control_frame, text="Apply Filter", command=self.apply_custom_filter)
        self.apply_filter_button.grid(row=0, column=6, padx=5, pady=5)

        self.search_label = ttk.Label(self.control_frame, text="Search Logs:")
        self.search_label.grid(row=1, column=0, padx=5, pady=5)

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self.control_frame, textvariable=self.search_var)
        self.search_entry.grid(row=1, column=1, padx=5, pady=5)

        self.search_button = ttk.Button(self.control_frame, text="Search", command=self.search_logs)
        self.search_button.grid(row=1, column=2, padx=5, pady=5)

        self.graph_type_var = tk.StringVar()
        self.graph_type_var.set("Line")
        self.graph_type_options = ttk.Combobox(self.control_frame, textvariable=self.graph_type_var)
        self.graph_type_options['values'] = ("Line", "Bar", "Scatter", "Histogram", "Boxplot", "Pie")
        self.graph_type_options.grid(row=1, column=3, padx=5, pady=5)

        self.update_graph_button = ttk.Button(self.control_frame, text="Update Graph", command=self.update_graph)
        self.update_graph_button.grid(row=1, column=4, padx=5, pady=5)

        # Traffic statistics frame widgets
        self.packet_count_label = ttk.Label(self.stats_frame, text="Packet Count: 0")
        self.packet_count_label.pack(pady=5)

        self.data_rate_label = ttk.Label(self.stats_frame, text="Data Rate: 0 B/s")
        self.data_rate_label.pack(pady=5)

        self.error_count_label = ttk.Label(self.stats_frame, text="Error Count: 0")
        self.error_count_label.pack(pady=5)

        # Network traffic graph frame
        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.ani = FuncAnimation(self.fig, self.update_graph, interval=1000, cache_frame_data=False)

        # Log frame widgets
        self.log_area = tk.Text(self.log_frame, state=tk.DISABLED, width=100, height=15)
        self.log_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.log_scrollbar = ttk.Scrollbar(self.log_frame, orient="vertical", command=self.log_area.yview)
        self.log_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.log_area.config(yscrollcommand=self.log_scrollbar.set)
        self.log_area.bind("<Button-1>", self.on_log_click)

        # Packet details frame widgets
        self.detail_area = tk.Text(self.detail_frame, state=tk.DISABLED, width=100, height=10)
        self.detail_area.pack(fill=tk.BOTH, expand=True)

        # Resource monitoring frame widgets
        self.cpu_label = ttk.Label(self.resource_frame, text="CPU Usage: 0%")
        self.cpu_label.pack(pady=5)

        self.memory_label = ttk.Label(self.resource_frame, text="Memory Usage: 0%")
        self.memory_label.pack(pady=5)

        # Status bar
        self.status_label = ttk.Label(self.root, text="Status: Ready")
        self.status_label.grid(row=4, column=0, columnspan=3, pady=5, sticky="ew")

        self.interface = "Wi-Fi"

        # Anomalies frame widgets
        self.anomaly_frame = ttk.LabelFrame(self.root, text="Detected Anomalies")
        self.anomaly_frame.grid(row=1, column=2, rowspan=2, padx=10, pady=10, sticky="nsew")

        self.anomaly_area = tk.Text(self.anomaly_frame, state=tk.DISABLED, width=50, height=10)
        self.anomaly_area.pack(fill=tk.BOTH, expand=True)

        self.anomaly_scrollbar = ttk.Scrollbar(self.anomaly_frame, orient="vertical", command=self.anomaly_area.yview)
        self.anomaly_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.anomaly_area.config(yscrollcommand=self.anomaly_scrollbar.set)


    def monitor_resources(self):
        if self.sniffing:
            cpu_usage = psutil.cpu_percent()
            memory_info = psutil.virtual_memory()
            self.cpu_label.config(text=f"CPU Usage: {cpu_usage}%")
            self.memory_label.config(text=f"Memory Usage: {memory_info.percent}%")
            self.resource_monitoring_id = self.root.after(5000, self.monitor_resources)

    def start_sniffing(self):
        try:
            if not self.sniffing:
                self.sniffing = True
                self.packet_processing.start_sniffing()
                self.start_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.NORMAL)
                self.status_label.config(text="Status: Sniffing")
                self.monitor_resources()

        except Exception as e:
            logging.error(f"Error starting sniffing in GUI: {e}")
            self.status_label.config(text="Status: Error starting sniffing.")
            self.stop_sniffing()

    def stop_sniffing(self):
        try:
            if self.sniffing:
                self.sniffing = False
                self.packet_processing.stop_sniffing()
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                self.status_label.config(text="Status: Stopped")

                if self.resource_monitoring_id:
                    self.root.after_cancel(self.resource_monitoring_id)
                    self.resource_monitoring_id = None

        except Exception as e:
            logging.error(f"Error stopping sniffing in GUI: {e}")
            self.status_label.config(text="Status: Error stopping sniffing.")

    def apply_custom_filter(self):
        self.packet_processing.apply_custom_filter(self.custom_filter_var.get())

    def search_logs(self):
        search_text = self.search_var.get()
        self.packet_processing.search_logs(search_text)

    def update_graph(self, frame=None):
        self.packet_processing.update_graph(self.ax, self.graph_type_var.get())
        self.canvas.draw()

    def log_message(self, message):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.config(state=tk.DISABLED)
        self.log_area.yview(tk.END)

    def show_packet_details(self, packet):
        details = self.packet_processing.decode_packet(packet)
        self.detail_area.config(state=tk.NORMAL)
        self.detail_area.delete(1.0, tk.END)
        self.detail_area.insert(tk.END, details)
        self.detail_area.config(state=tk.DISABLED)

    def on_log_click(self, event):
        index = self.log_area.index("@%s,%s" % (event.x, event.y))
        line_number = int(index.split('.')[0])
        line_text = self.log_area.get(f"{line_number}.0", f"{line_number}.end")
        if hasattr(self, 'highlighted_line'):
            self.log_area.tag_remove("highlight", f"{self.highlighted_line}.0", f"{self.highlighted_line}.end")
        self.log_area.tag_add("highlight", f"{line_number}.0", f"{line_number}.end")
        self.log_area.tag_config("highlight", background="yellow")
        self.highlighted_line = line_number
        packet_data = self.packet_processing.get_packet_by_summary(line_text)
        if packet_data:
            self.show_packet_details(packet_data)

    def log_anomaly(self, anomaly_message):
        self.anomaly_area.config(state=tk.NORMAL)
        self.anomaly_area.insert(tk.END, anomaly_message + "\n")
        self.anomaly_area.config(state=tk.DISABLED)
        self.anomaly_area.yview(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
