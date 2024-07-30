import tkinter as tk
from tkinter import ttk
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
from packet_processing import PacketProcessing
from filters import FILTERS

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Packet Sniffer Dashboard")

        self.packet_processing = PacketProcessing(self)
        self.create_widgets()

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

        self.apply_filter_button = ttk.Button(self.control_frame, text="Apply Custom Filter", command=self.apply_custom_filter)
        self.apply_filter_button.grid(row=0, column=6, padx=5, pady=5)

        self.search_label = ttk.Label(self.control_frame, text="Search:")
        self.search_label.grid(row=1, column=0, padx=5, pady=5)

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self.control_frame, textvariable=self.search_var)
        self.search_entry.grid(row=1, column=1, padx=5, pady=5)

        self.search_button = ttk.Button(self.control_frame, text="Search", command=self.search_logs)
        self.search_button.grid(row=1, column=2, padx=5, pady=5)

        self.graph_type_label = ttk.Label(self.control_frame, text="Graph Type:")
        self.graph_type_label.grid(row=1, column=3, padx=5, pady=5)

        self.graph_type_var = tk.StringVar()
        self.graph_type_var.set("Line")
        self.graph_type_options = ttk.Combobox(self.control_frame, textvariable=self.graph_type_var)
        self.graph_type_options['values'] = ("Line", "Bar", "Scatter", "Histogram", "Boxplot", "Pie")
        self.graph_type_options.grid(row=1, column=4, padx=5, pady=5)

        self.update_graph_button = ttk.Button(self.control_frame, text="Update Graph", command=self.update_graph)
        self.update_graph_button.grid(row=1, column=5, padx=5, pady=5)

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

        # Status bar
        self.status_label = ttk.Label(self.root, text="Status: Ready")
        self.status_label.grid(row=4, column=0, columnspan=2, pady=5, sticky="ew")

        self.interface = "Wi-Fi"

    def start_sniffing(self):
        self.packet_processing.start_sniffing()

    def stop_sniffing(self):
        self.packet_processing.stop_sniffing()

    def apply_custom_filter(self):
        self.packet_processing.apply_custom_filter(self.custom_filter_var.get())

    def search_logs(self):
        search_text = self.search_var.get()
        self.packet_processing.search_logs(search_text)

    def update_graph(self):
        self.packet_processing.update_graph(self.ax, self.graph_type_var.get())
        self.canvas.draw()

    def log_message(self, message):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.config(state=tk.DISABLED)

    def show_packet_details(self, packet):
        details = self.packet_processing.decode_packet(packet)
        self.detail_area.config(state=tk.NORMAL)
        self.detail_area.delete(1.0, tk.END)
        self.detail_area.insert(tk.END, details)
        self.detail_area.config(state=tk.DISABLED)

    def update_graph(self, frame):
        self.packet_processing.update_graph(self.ax, self.graph_type_var.get())
        self.canvas.draw()

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

