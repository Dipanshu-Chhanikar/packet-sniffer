import tkinter as tk
from tkinter import ttk, scrolledtext

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Packet Sniffer")

        # Frame for Controls
        self.control_frame = ttk.Frame(root, padding="10")
        self.control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Start Button
        self.start_button = ttk.Button(self.control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=5, pady=5)

        # Stop Button
        self.stop_button = ttk.Button(self.control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)

        # Log Area
        self.log_area = scrolledtext.ScrolledText(root, width=100, height=20, state=tk.DISABLED)
        self.log_area.grid(row=1, column=0, padx=10, pady=10)

        # Status Label
        self.status_label = ttk.Label(root, text="Status: Idle")
        self.status_label.grid(row=2, column=0, pady=5)

    def start_sniffing(self):
        self.status_label.config(text="Status: Sniffing...")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        # Start sniffing logic will be added here

    def stop_sniffing(self):
        self.status_label.config(text="Status: Idle")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        # Stop sniffing logic will be added here

    def log_message(self, message):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.yview(tk.END)
        self.log_area.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
