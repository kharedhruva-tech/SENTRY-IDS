import os

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'ids-super-secret-key-39f8f41e')
    
    # SQLAlchemy configuration
    # Saves db as ids_database.db inside the instance folder or root directory
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'ids_database.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Intrusion Detection System configuration thresholds
    # Port scan: threshold of unique ports hit by a single source IP in window
    PORT_SCAN_THRESHOLD = 15
    PORT_SCAN_WINDOW = 10  # seconds
    
    # DDoS Flood: packets per second from a single source IP
    DDOS_THRESHOLD_PPS = 100
    DDOS_WINDOW = 5  # seconds
    
    # Brute Force Connection Rate (e.g. hits on auth ports)
    BRUTE_FORCE_THRESHOLD = 8
    BRUTE_FORCE_WINDOW = 10  # seconds
    
    # Threat Intelligence Config
    GEOIP_API_URL = "http://ip-api.com/json/"
    GEOIP_CACHE_TIMEOUT = 3600  # cache locations for 1 hour
    
    # Machine Learning config
    ML_MODEL_FILENAME = "ids_anomaly_model.joblib"
    ML_FEATURES = ["protocol", "src_port", "dst_port", "length", "packet_rate", "payload_entropy"]
