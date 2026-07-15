import re
from datetime import datetime
from config import Config
from ml_engine import ml_engine
from database import BlacklistIP

class ThreatDetector:
    def __init__(self):
        # Stateful tracking for heuristic analysis
        # Format: { src_ip: set(dst_ports) }
        self.port_scan_state = {}
        # Format: { src_ip: [timestamps] }
        self.ddos_state = {}
        # Format: { src_ip: { dst_port: [timestamps] } }
        self.brute_force_state = {}
        
        # Cooldown/throttling state to prevent alert flooding
        # Format: { (src_ip, category): last_alert_timestamp }
        self.alert_cooldowns = {}
        self.cooldown_interval = 10  # seconds
        
        # Regex signatures for payload scanning
        self.signatures = {
            "SQL Injection": re.compile(
                r"(?i)(UNION\s+(ALL\s+)?SELECT|SELECT\s+.*\s+FROM|OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|'\s*OR\s*['\"]?['\"]?\s*=\s*['\"]?|UNION\s+SELECT\s+NULL)",
                re.IGNORECASE
            ),
            "Cross-Site Scripting (XSS)": re.compile(
                r"(?i)(<script.*?>|javascript:|onload\s*=|onerror\s*=|alert\(|document\.cookie|<img\s+src\s*=\s*['\"]?javascript:)",
                re.IGNORECASE
            ),
            "Remote Code Execution (RCE)": re.compile(
                r"(?i)(\$\{\s*jndi\s*:|/bin/sh|/bin/bash|cmd\.exe|powershell\.exe|wget\s+http|curl\s+http)",
                re.IGNORECASE
            ),
            "Path Traversal": re.compile(
                r"(?i)(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/windows/win\.ini|boot\.ini)",
                re.IGNORECASE
            )
        }

    def _should_throttle(self, src_ip, category):
        """Returns True if an alert of this category from this IP was triggered recently."""
        now = datetime.utcnow()
        key = (src_ip, category)
        if key in self.alert_cooldowns:
            last_alert_time = self.alert_cooldowns[key]
            if (now - last_alert_time).total_seconds() < self.cooldown_interval:
                return True
        self.alert_cooldowns[key] = now
        return False

    def check_blacklist(self, src_ip, db_session=None):
        """Check if the source IP is blacklisted in SQLite database."""
        if db_session:
            # Query from session if available
            blacklisted = db_session.query(BlacklistIP).filter_by(ip_address=src_ip).first()
            if blacklisted:
                return blacklisted.description or "Known malicious IP address"
        return None

    def analyze_packet(self, packet_dict, packet_rate, db_session=None):
        """
        Analyze packet metadata and payload.
        Returns a dictionary representing an Alert if threat is detected, otherwise None.
        """
        src_ip = packet_dict.get("src_ip")
        dst_ip = packet_dict.get("dst_ip")
        protocol = packet_dict.get("protocol")
        src_port = packet_dict.get("src_port")
        dst_port = packet_dict.get("dst_port")
        length = packet_dict.get("length", 0)
        payload = packet_dict.get("payload_summary", "")
        
        now = datetime.utcnow()
        
        # 1. Threat Intel Blacklist Check
        blacklist_reason = self.check_blacklist(src_ip, db_session)
        if blacklist_reason:
            if not self._should_throttle(src_ip, "Threat Intel Blacklist"):
                return {
                    "category": "Threat Intel Blacklist",
                    "severity": "High",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "message": f"Connection from blacklisted IP: {src_ip} ({blacklist_reason})",
                    "is_ml": False,
                    "confidence": 1.0
                }

        # 2. Stateful Port Scan Detection (Heuristic)
        if dst_port is not None and protocol in ["TCP", "UDP"]:
            # Initialize IP states
            if src_ip not in self.port_scan_state:
                self.port_scan_state[src_ip] = {"ports": set(), "start_time": now}
            
            # Reset state window if expired
            state = self.port_scan_state[src_ip]
            if (now - state["start_time"]).total_seconds() > Config.PORT_SCAN_WINDOW:
                state["ports"] = set()
                state["start_time"] = now
                
            state["ports"].add(dst_port)
            
            if len(state["ports"]) > Config.PORT_SCAN_THRESHOLD:
                if not self._should_throttle(src_ip, "Port Scan"):
                    # Clear state to prevent repeating
                    state["ports"] = set()
                    return {
                        "category": "Port Scan",
                        "severity": "High",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "message": f"Port scan detected from {src_ip}. Contacted {Config.PORT_SCAN_THRESHOLD}+ unique ports in {Config.PORT_SCAN_WINDOW}s.",
                        "is_ml": False,
                        "confidence": 0.95
                    }

        # 3. Stateful DDoS Flood Detection (Heuristic)
        if src_ip not in self.ddos_state:
            self.ddos_state[src_ip] = []
        
        # Slide window
        self.ddos_state[src_ip].append(now)
        self.ddos_state[src_ip] = [t for t in self.ddos_state[src_ip] if (now - t).total_seconds() <= Config.DDOS_WINDOW]
        
        pps = len(self.ddos_state[src_ip]) / float(Config.DDOS_WINDOW)
        if pps > Config.DDOS_THRESHOLD_PPS:
            if not self._should_throttle(src_ip, "DDoS Attempt"):
                return {
                    "category": "DDoS Attempt",
                    "severity": "Critical",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "message": f"Potential DDoS flood from {src_ip}. Packet rate: {pps:.1f} packets/sec (Threshold: {Config.DDOS_THRESHOLD_PPS}).",
                    "is_ml": False,
                    "confidence": 0.98
                }

        # 4. Brute Force Login / Connection Attempt (Heuristic)
        auth_ports = [22, 21, 23, 3389, 3306, 1433] # SSH, FTP, Telnet, RDP, MySQL, MSSQL
        if dst_port in auth_ports and protocol == "TCP":
            if src_ip not in self.brute_force_state:
                self.brute_force_state[src_ip] = {}
            if dst_port not in self.brute_force_state[src_ip]:
                self.brute_force_state[src_ip][dst_port] = []
                
            self.brute_force_state[src_ip][dst_port].append(now)
            # Filter window
            self.brute_force_state[src_ip][dst_port] = [t for t in self.brute_force_state[src_ip][dst_port] if (now - t).total_seconds() <= Config.BRUTE_FORCE_WINDOW]
            
            attempts = len(self.brute_force_state[src_ip][dst_port])
            if attempts > Config.BRUTE_FORCE_THRESHOLD:
                if not self._should_throttle(src_ip, f"Brute Force Port {dst_port}"):
                    return {
                        "category": "Brute Force Attempt",
                        "severity": "High",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "message": f"Suspicious connection spikes on authentication port {dst_port} from {src_ip} ({attempts} connections in {Config.BRUTE_FORCE_WINDOW}s).",
                        "is_ml": False,
                        "confidence": 0.90
                    }

        # 5. Payload Signature Check
        if payload:
            for threat_name, regex in self.signatures.items():
                if regex.search(payload):
                    if not self._should_throttle(src_ip, threat_name):
                        severity = "Critical" if threat_name in ["Remote Code Execution (RCE)", "SQL Injection"] else "High"
                        return {
                            "category": threat_name,
                            "severity": severity,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "message": f"Signature-based {threat_name} pattern matched in packet payload: '{payload[:60]}...'",
                            "is_ml": False,
                            "confidence": 1.0
                        }

        # 6. Machine Learning Anomaly Detection (Anomaly Engine)
        # We perform this analysis as a fallback to detect unknown threats
        is_ml_anomaly, confidence = ml_engine.predict_anomaly(
            protocol_str=protocol,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            packet_rate=packet_rate,
            payload=payload
        )
        if is_ml_anomaly:
            if not self._should_throttle(src_ip, "ML Anomaly"):
                # ML flags it. We classify severity based on confidence
                severity = "High" if confidence > 0.8 else "Medium"
                return {
                    "category": "ML Anomaly",
                    "severity": severity,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "message": f"ML Anomaly Engine flagged connection behavior as suspicious (Confidence: {confidence:.0%}).",
                    "is_ml": True,
                    "confidence": confidence
                }

        # No threats detected
        return None

# Global detector instance
threat_detector = ThreatDetector()
