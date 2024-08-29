# Real-Time Packet Sniffer with Anomaly Detection and GUI

## Project Overview
This project is a **real-time packet sniffer** built using Python, featuring a **Graphical User Interface (GUI)** developed with Tkinter. It captures, processes, and analyzes network traffic in real time, providing detailed packet summaries, filtering options, and anomaly detection based on statistical models.

The project supports multiple network protocols including **TCP**, **UDP**, **IP**, **SMTP** and more, and allows users to visualize traffic through various graph types. It also includes resource monitoring (CPU and memory) and a search functionality for packet logs.

## Key Features

### 1. Real-Time Packet Sniffing
- Captures live network packets using the **Scapy** library.
- Supports custom filtering for protocols such as **TCP**, **UDP**, **IP**, **HTTP**, **HTTPS**, and more.
- Packet summaries are displayed in real-time in the GUI.

### 2. Anomaly Detection
- Detects anomalies in network traffic using **statistical models** (Z-score based) to find unusual patterns.
- Displays alerts for anomalous packets directly in the GUI.
  
### 3. Graphical User Interface (GUI)
- **Start/Stop** buttons to control the sniffing process.
- Live visualization of packet statistics through various **graph types** (Line, Bar, Scatter, Histogram, Boxplot, Pie).
- Detailed logs with the ability to search and highlight specific terms.
  
### 4. Resource Monitoring
- Monitors system resources such as **CPU** and **Memory** usage while sniffing is in progress.

### 5. Log Search and Packet Details
- Allows users to search packet logs and view detailed packet information.
- Highlights matching terms in the log output.

## How It Works

1. **Packet Sniffing**: Captures network packets from the selected network interface and filters them based on user input.
2. **Anomaly Detection**: Analyzes packet sizes and other features in real-time, flagging potential anomalies.
3. **Graphical Representation**: Displays network traffic using different graph types for easy interpretation of the data.

## Installation

### Prerequisites
Make sure you have the following installed:
- Python 3.x
- Scapy (`pip install scapy`)
- Psutil (`pip install psutil`)
- Matplotlib (`pip install matplotlib`)
- Numpy (`pip install numpy`)
- Tkinter (comes pre-installed with Python on most systems)
- PCAP ('sudo apt-get install libpcap-dev') #if you are using linux
        For Windows, install WinPcap or Npcap.

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/Dipanshu-Chhanikar/packet-sniffer.git

2. Install dependencies:
   ```bash
   pip install -r requirements.txt

3. Run the application:
   ```bash
   python main.py

## GUI Screenshot
![GUI Screenshot](https://github.com/Dipanshu-Chhanikar/packet-sniffer/raw/main/ss.jpg)

### Connect with Me
If you have any questions, feedback, or would like to collaborate, feel free to connect with me on [LinkedIn](https://www.linkedin.com/in/dipanshu-chhanikar13)
