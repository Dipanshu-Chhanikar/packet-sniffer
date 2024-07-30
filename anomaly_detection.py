import numpy as np
from scapy.all import IP, TCP, UDP

class AnomalyDetector:
    def __init__(self, threshold=2.0):
        self.threshold = threshold
        self.packet_stats = []

    def is_anomalous_packet(self, packet):
        if IP in packet:
            if TCP in packet:
                length = len(packet[TCP])
            elif UDP in packet:
                length = len(packet[UDP])
            else:
                length = len(packet[IP])

            self.packet_stats.append(length)
            mean_length = np.mean(self.packet_stats)
            std_length = np.std(self.packet_stats)

            if std_length == 0:
                return False

            z_score = (length - mean_length) / std_length
            return abs(z_score) > self.threshold
        return False
