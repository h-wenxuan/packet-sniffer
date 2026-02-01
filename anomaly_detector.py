"""
AI-powered anomaly detection module for network traffic analysis.
"""
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class WindowAggregator:
    """Aggregates packet features within time windows for anomaly detection."""
    
    def __init__(self, window_seconds=1.0):
        self.window_seconds = window_seconds
        self.reset()

    def reset(self):
        """Reset all window counters."""
        self.start_time = time.time()
        self.packet_count = 0
        self.byte_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.syn_count = 0
        self.src_ips = set()
        self.dst_ips = set()
        self.dst_ports = set()
        self.dns_count = 0
        # Store recent packets for anomaly context
        self.recent_packets = []

    def add_packet(self, pkt):
        """Add a packet to the current window."""
        self.packet_count += 1
        self.byte_count += pkt.get("size", 0)

        proto = pkt.get("protocol", 0)
        if proto == 6:  # TCP
            self.tcp_count += 1
            flags = pkt.get("flags", {})
            if flags.get("SYN", 0) == 1:
                self.syn_count += 1
        elif proto == 17:  # UDP
            self.udp_count += 1
            if pkt.get("src_port") == 53 or pkt.get("dest_port") == 53:
                self.dns_count += 1
        elif proto == 1:  # ICMP
            self.icmp_count += 1

        src_ip = pkt.get("src_ip", "0.0.0.0")
        dst_ip = pkt.get("dest_ip", "0.0.0.0")
        
        self.src_ips.add(src_ip)
        self.dst_ips.add(dst_ip)
        
        if pkt.get("dest_port") is not None:
            self.dst_ports.add(pkt.get("dest_port"))
        
        # Store packet summary for anomaly context (keep last 50)
        pkt_summary = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": pkt.get("src_port"),
            "dest_port": pkt.get("dest_port"),
            "protocol": pkt.get("protocol"),
            "size": pkt.get("size", 0)
        }
        self.recent_packets.append(pkt_summary)
        if len(self.recent_packets) > 50:
            self.recent_packets.pop(0)

    def window_ready(self):
        """Check if the current window is complete."""
        return (time.time() - self.start_time) >= self.window_seconds

    def extract_features(self):
        """Extract numerical features for anomaly detection."""
        duration = max(time.time() - self.start_time, 1e-6)
        total = max(self.packet_count, 1)

        features = [
            self.packet_count / duration,    # packets per sec
            self.byte_count / duration,    # bytes per sec
            self.tcp_count / total,    # tcp ratio
            self.udp_count / total,    # udp ratio
            self.icmp_count / total,    # icmp ratio
            self.syn_count,    # syn count
            len(self.src_ips),    # unique src IPs
            len(self.dst_ports),    # unique dst ports
            self.dns_count    # dns count
        ]
        return features
    
    def get_ip_context(self):
        """Get IP address context for anomaly reporting."""
        return {
            "src_ips": list(self.src_ips),
            "dst_ips": list(self.dst_ips),
            "recent_packets": self.recent_packets[-10:] if self.recent_packets else []
        }

class AnomalyDetector:
    """Machine learning-based network anomaly detector."""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.05,   # 5% expected anomalies
            random_state=42
        )
        self.anomaly_threshold = 0.05
        self.is_trained = False
        self.baseline_features = []
        self.training_scores = []

    def add_baseline_features(self, features):
        """Add features to the baseline dataset."""
        self.baseline_features.append(features)

    def train_model(self):
        """Train the anomaly detection model on baseline data."""
        if len(self.baseline_features) < 30:
            raise ValueError(f"Need at least 30 windows for baseline. Currently have {len(self.baseline_features)} windows.")

        X = np.array(self.baseline_features)
        Xs = self.scaler.fit_transform(X)

        # Track training score evolution
        self.training_scores.clear()
        for i in range(10, len(Xs), 5):
            self.model.fit(Xs[:i])
            scores = self.model.decision_function(Xs[:i])
            self.training_scores.append(np.mean(scores))

        # Final training
        self.model.fit(Xs)
        
        # Enhanced threshold calculation
        baseline_scores = self.model.decision_function(Xs)
        mean_score = np.mean(baseline_scores)
        std_score = np.std(baseline_scores)
        
        # Use multiple methods to determine threshold and pick the most reasonable
        percentile_10 = np.percentile(baseline_scores, 10)
        percentile_5 = np.percentile(baseline_scores, 5)
        std_based = mean_score - 2 * std_score  # 2 standard deviations below mean
        
        # Choose the most reasonable threshold
        candidate_thresholds = [percentile_10, percentile_5, std_based]
        # Remove any that are too close to zero or positive
        valid_thresholds = [t for t in candidate_thresholds if t < -0.01]
        
        if valid_thresholds:
            self.anomaly_threshold = max(valid_thresholds)  # Least strict of the valid options
        else:
            self.anomaly_threshold = percentile_10  # Fallback to 10th percentile
        
        self.is_trained = True
        
        print(f"[ANOMALY DETECTOR] Model trained on {len(self.baseline_features)} windows")
        print(f"[ANOMALY DETECTOR] Anomaly threshold: {self.anomaly_threshold:.3f}")
        
        return {
            'threshold': self.anomaly_threshold,
            'baseline_windows': len(self.baseline_features),
            'training_scores': self.training_scores.copy()
        }

    def detect_anomaly(self, features):
        """Detect if the given features represent an anomaly."""
        if not self.is_trained:
            raise ValueError("Model must be trained before detecting anomalies")
        
        Xs = self.scaler.transform([features])
        score = self.model.decision_function(Xs)[0]
        
        is_anomaly = score < self.anomaly_threshold
        
        return {
            'is_anomaly': is_anomaly,
            'score': score,
            'threshold': self.anomaly_threshold,
        }

    def clear_baseline(self):
        """Clear baseline data to start fresh collection."""
        self.baseline_features.clear()
        self.training_scores.clear()
        self.is_trained = False

    def get_training_progress(self):
        """Get current training progress information."""
        return {
            'baseline_count': len(self.baseline_features),
            'is_trained': self.is_trained,
            'training_scores': self.training_scores.copy()
        }