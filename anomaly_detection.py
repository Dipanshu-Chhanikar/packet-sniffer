# anomaly_detection.py
import numpy as np

class AnomalyDetector:
    def __init__(self, threshold=2.0):
        self.threshold = threshold
        self.packet_sizes = []
        self.mean_size = 0
        self.std_dev_size = 0

    def update_statistics(self, packet_size):
        self.packet_sizes.append(packet_size)
        if len(self.packet_sizes) > 1:
            self.mean_size = np.mean(self.packet_sizes)
            self.std_dev_size = np.std(self.packet_sizes)
        else:
            self.mean_size = packet_size
            self.std_dev_size = 0

    def detect_anomaly(self, packet_size):
        if self.std_dev_size <= 0:
            return False  # Not enough data to detect anomalies or standard deviation is zero

        z_score = (packet_size - self.mean_size) / self.std_dev_size
        return abs(z_score) > self.threshold

    def process_packet(self, packet_size):
        self.update_statistics(packet_size)
        if self.detect_anomaly(packet_size):
            return "Anomaly detected: unusual packet size"
        return None
