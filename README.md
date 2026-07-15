# SENTRY-IDS // Advanced Intrusion Detection System & Dashboard

Sentry-IDS is a professional, cybersecurity-themed Intrusion Detection System (IDS) featuring a modern dark/neon glassmorphic web dashboard. It combines traditional rule-based threat signature matching and heuristic counters with machine learning anomaly detection to track and isolate malicious network activity.

---

## Key Features

1. **Real-time Packet Analysis**: Captures live traffic (TCP, UDP, ICMP) utilizing Scapy.
2. **Dual-engine Detection System**:
   - **Heuristics**: Tracks unique ports hit (Port Scan), packet frequencies (DDoS), and rapid auth connections (Brute-Force).
   - **Signatures**: Payload scanning for SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, and Remote Code Execution (RCE) patterns.
3. **Machine Learning Classifier**: Trains an unsupervised **Isolation Forest** model to detect anomaly profiles (zero-day spikes, unusual ports, high-entropy encrypted C2 beacons).
4. **Threat Intelligence Integration**: Locally cached **GeoIP Geolocation lookup** maps coordinates, country, and ISP details of external attacking IPs.
5. **Role-Based Access Control**: Separate permissions for **Admin** (retrain models, modify blacklist, add users), **Analyst** (mute/resolve incidents, export reports), and **Viewer** (read-only grid review).
6. **Executive Reporting**: Dynamic on-the-fly downloads for raw threat logs in **CSV** format and summary reports in **PDF** (rendered with tables and metrics cards).
7. **Zero-Configuration Fallback**: Instantly starts in **Simulated Traffic mode** if Scapy permissions or network driver captures are denied, ensuring the dashboard flows with data out-of-the-box.

---

## Project Structure

```
c:\Users\Dhruva\OneDrive\Desktop\pp\
├── app.py                     # Main Flask web controller, session routing, and SSE APIs
├── config.py                  # Threat thresholds, database files, and model configs
├── database.py                # Flask-SQLAlchemy models (User, PacketLog, Alert, BlacklistIP)
├── detector.py                # Pattern-matching signatures and stateful scan thresholds
├── ml_engine.py               # Feature preprocessors, Shannon payload entropy, IsolationForest model
├── report_generator.py        # ReportLab PDF design layouts and CSV string writers
├── requirements.txt           # Required third-party libraries list
├── sniffer.py                 # Thread manager wrapping Scapy and high-fidelity Traffic Simulator
├── threat_intel.py            # GeoIP API caching services and IP blacklist checkers
├── static/
│   ├── css/
│   │   └── dashboard.css      # Neon-cyberpunk custom glassmorphism stylesheet
│   └── js/
│       ├── auth.js            # Frontend credentials form password validators
│       └── dashboard.js       # Chart.js updates, SSE generators listeners, and modal detail actions
└── templates/
    ├── layout.html            # Master frame layout containing navigation sidebar
    ├── login.html             # Login form
    ├── register.html          # Registration form
    ├── dashboard.html         # Live stats cards, chart grids, live streams
    ├── alerts.html            # Filtering lists, alert resolution models
    ├── logs.html              # Search grid interfaces and report launchers
    └── settings.html          # ML retraining logs and IP blocking forms
```

---

## Installation & Setup

### 1. Prerequisites
- **Python 3.8+** must be installed on your system.
- *(Optional for Live Sniffing)*: **Npcap** (Windows) or **libpcap** (Linux/macOS) is required to run live network traffic sniffing. If absent, Sentry-IDS will gracefully fall back to generating simulated network events automatically.

### 2. Install Dependencies
Open a terminal in the project directory and run:
```bash
pip install -r requirements.txt
```

### 3. Run Sentry-IDS
Execute the server using:
```bash
python app.py
```
The server will initialize the SQLite database, seed default users, construct the initial Machine Learning model, start the packet sniffer, and host the web console locally.

**Console URL**: `http://127.0.0.1:5000`

---

## Seed Accounts (Ready for Use)

You can log in immediately using these default accounts:

| Username | Password | Role | Console Privileges |
| :--- | :--- | :--- | :--- |
| **`admin`** | `admin123` | **Admin** | Retrain ML model, manage blacklists, configure users, download reports, read dashboards. |
| **`analyst`** | `analyst123` | **Analyst** | Change alert status (resolve/mute), inspect IP geolocations, download reports. |
| **`viewer`** | `viewer123` | **Viewer** | Read-only dashboards and packet tables. |

You can also use the registration form to create custom usernames matching these roles.

---

## Core Technologies
- **Backend Framework**: Flask
- **Database Engine**: SQLite (Flask-SQLAlchemy ORM)
- **Real-Time Data Flow**: Server-Sent Events (SSE)
- **Machine Learning**: Scikit-Learn (Isolation Forest)
- **Packet Extraction**: Scapy
- **Visualizations**: Chart.js (Line, Doughnut, Bar charts)
- **PDF Compilation**: ReportLab Flowables
