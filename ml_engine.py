import numpy as np
import pandas as pd
import pickle
import os
import math
from sklearn.ensemble import IsolationForest

class MLEngine:
    def __init__(self, model_path="ids_anomaly_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.feature_names = ["protocol", "src_port", "dst_port", "length", "packet_rate", "payload_entropy"]
        self.protocol_map = {"TCP": 6, "UDP": 17, "ICMP": 1, "OTHER": 0}
        
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data string or bytes to detect obfuscated/encrypted payloads."""
        if not data:
            return 0.0
        
        # Convert to bytes if it's a string
        if isinstance(data, str):
            data = data.encode('utf-8', errors='ignore')
            
        if not data:
            return 0.0
            
        entropy = 0.0
        length = len(data)
        frequencies = {}
        
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
            
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
            
        return round(entropy, 2)

    def preprocess_packet(self, protocol_str, src_port, dst_port, length, packet_rate, payload):
        """Convert a packet's metadata into a feature array."""
        protocol_num = self.protocol_map.get(str(protocol_str).upper(), 0)
        entropy = self.calculate_entropy(payload)
        
        # Ensure ports are valid integers
        src_p = int(src_port) if src_port is not None else 0
        dst_p = int(dst_port) if dst_port is not None else 0
        pkt_len = int(length) if length is not None else 0
        
        features = np.array([[protocol_num, src_p, dst_p, pkt_len, float(packet_rate), entropy]])
        return features

    def train_model(self, data_samples=None):
        """Train the Isolation Forest model. Synthesizes a training set if none is provided."""
        if data_samples is None:
            # Synthesize training dataset
            print("[ML Engine] No training data provided. Generating synthetic dataset...")
            np.random.seed(42)
            
            # 1. Normal traffic (80% of data)
            n_normal = 2000
            normal_protocols = np.random.choice([6, 17], size=n_normal, p=[0.75, 0.25])  # TCP/UDP
            normal_src_ports = np.random.randint(1024, 65535, size=n_normal)
            normal_dst_ports = np.random.choice([80, 443, 53, 123], size=n_normal, p=[0.4, 0.4, 0.15, 0.05])
            normal_lengths = np.random.normal(500, 300, size=n_normal).clip(40, 1500)
            normal_rates = np.random.exponential(2, size=n_normal).clip(0.1, 10)
            normal_entropies = np.random.normal(3.5, 0.8, size=n_normal).clip(0, 6)
            
            normal_df = pd.DataFrame({
                "protocol": normal_protocols,
                "src_port": normal_src_ports,
                "dst_port": normal_dst_ports,
                "length": normal_lengths,
                "packet_rate": normal_rates,
                "payload_entropy": normal_entropies
            })
            
            # 2. Port scans (anomalies)
            n_scan = 100
            scan_protocols = np.ones(n_scan) * 6  # TCP
            scan_src_ports = np.random.randint(40000, 50000, size=n_scan)
            scan_dst_ports = np.random.randint(1, 1024, size=n_scan)  # hitting many low system ports
            scan_lengths = np.random.choice([40, 60], size=n_scan)  # small SYN packets
            scan_rates = np.random.normal(50, 10, size=n_scan).clip(20, 100)  # high frequency
            scan_entropies = np.zeros(n_scan)  # no payload
            
            scan_df = pd.DataFrame({
                "protocol": scan_protocols,
                "src_port": scan_src_ports,
                "dst_port": scan_dst_ports,
                "length": scan_lengths,
                "packet_rate": scan_rates,
                "payload_entropy": scan_entropies
            })
            
            # 3. DDoS attempts (anomalies)
            n_ddos = 100
            ddos_protocols = np.random.choice([6, 17], size=n_ddos)
            ddos_src_ports = np.random.randint(1024, 65535, size=n_ddos)
            ddos_dst_ports = np.ones(n_ddos) * 80  # hitting web port
            ddos_lengths = np.ones(n_ddos) * 64  # small flood packets
            ddos_rates = np.random.normal(500, 100, size=n_ddos).clip(150, 1000)  # extremely high rate
            ddos_entropies = np.random.normal(1.0, 0.5, size=n_ddos).clip(0, 3)
            
            ddos_df = pd.DataFrame({
                "protocol": ddos_protocols,
                "src_port": ddos_src_ports,
                "dst_port": ddos_dst_ports,
                "length": ddos_lengths,
                "packet_rate": ddos_rates,
                "payload_entropy": ddos_entropies
            })
            
            # 4. Encrypted Malicious C2 / High Entropy (anomalies)
            n_c2 = 50
            c2_protocols = np.ones(n_c2) * 6
            c2_src_ports = np.random.randint(1024, 65535, size=n_c2)
            c2_dst_ports = np.random.choice([8080, 4444, 9999], size=n_c2)  # unusual listener ports
            c2_lengths = np.random.randint(800, 1500, size=n_c2)
            c2_rates = np.random.normal(5, 2, size=n_c2).clip(1, 15)
            c2_entropies = np.random.uniform(7.2, 7.95, size=n_c2)  # extremely high entropy (packed/encrypted payload)
            
            c2_df = pd.DataFrame({
                "protocol": c2_protocols,
                "src_port": c2_src_ports,
                "dst_port": c2_dst_ports,
                "length": c2_lengths,
                "packet_rate": c2_rates,
                "payload_entropy": c2_entropies
            })
            
            df_train = pd.concat([normal_df, scan_df, ddos_df, c2_df], ignore_index=True)
            X = df_train[self.feature_names].values
        else:
            # Custom training set (e.g. from SQLite history logs)
            X = np.array(data_samples)
            
        print(f"[ML Engine] Training Isolation Forest model on {len(X)} samples...")
        self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.model.fit(X)
        
        # Save model
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            print(f"[ML Engine] Model trained successfully and saved to {self.model_path}")
        except Exception as e:
            print(f"[ML Engine] Failed to save model: {e}")

    def load_model(self):
        """Loads model file. If not found, initializes training."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print(f"[ML Engine] Model loaded successfully from {self.model_path}")
                return True
            except Exception as e:
                print(f"[ML Engine] Failed to load model: {e}. Retraining...")
                
        self.train_model()
        return True

    def predict_anomaly(self, protocol_str, src_port, dst_port, length, packet_rate, payload):
        """
        Classify a packet.
        Returns:
            is_anomaly (bool): True if model flags packet as anomaly, False otherwise.
            confidence (float): Confidence score (0.0 to 1.0).
        """
        if self.model is None:
            self.load_model()
            
        features = self.preprocess_packet(protocol_str, src_port, dst_port, length, packet_rate, payload)
        
        # Isolation Forest prediction: 1 = normal, -1 = anomaly
        prediction = self.model.predict(features)[0]
        
        # Raw score: lower values indicate anomalies (usually < 0)
        raw_score = self.model.decision_function(features)[0]
        
        # Compute confidence score
        # The decision function returns scores in range [-0.5, 0.5] approximately.
        # Let's map this dynamically:
        if prediction == -1:
            is_anomaly = True
            # Anomalous: maps raw score in e.g. [-0.3, 0] to [0.5, 1.0]
            confidence = min(1.0, max(0.5, 0.5 + abs(raw_score) * 2.5))
        else:
            is_anomaly = False
            # Normal: maps raw score in e.g. [0, 0.3] to [0.5, 1.0]
            confidence = min(1.0, max(0.5, 0.5 + raw_score * 2.0))
            
        return is_anomaly, round(float(confidence), 2)

# Global engine instance
ml_engine = MLEngine()
