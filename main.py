import tkinter as tk
from gui import PacketSnifferGUI

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
