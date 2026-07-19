# 🛡️ SENTRY-IDS

**Intelligent Network Intrusion Detection System**

SENTRY-IDS is a Python-based Intrusion Detection System (IDS) that captures live network traffic, analyzes it using both signature-based rules and a machine learning anomaly model, and surfaces threats through a Flask web dashboard and companion Android app.

[![Live Demo](https://img.shields.io/badge/%F0%9F%9A%80_LIVE_DEMO-Try_SENTRY--IDS-brightgreen?style=for-the-badge)](https://sentry-ids.onrender.com)
[![Download APK](https://img.shields.io/badge/%F0%9F%93%B1_DOWNLOAD-APK-blue?style=for-the-badge&logo=android&logoColor=white)](https://github.com/kharedhruva-tech/SENTRY-IDS/raw/main/SENTRY_IDS.apk)

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat-square&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)

**🔗 Live Application:** [sentry-ids.onrender.com](https://sentry-ids.onrender.com)

---

## 📖 Overview

Modern networks face constant threats — brute-force attempts, port scans, malware callbacks, and unauthorized access. **SENTRY-IDS** monitors live traffic, flags suspicious behavior in real time, and gives analysts a clear, actionable view of what's happening on the network.

It combines three detection layers:

- **Packet-level sniffing** for raw traffic capture
- **Rule/signature-based detection** for known attack patterns
- **ML-based anomaly detection** for identifying unusual behavior that doesn't match a known signature

Results are logged to a database, enriched with threat intelligence, and available as generated reports and a live dashboard — with a native Android app for on-the-go monitoring.

---

## ✨ Features

- ⚡ **Real-time traffic capture** via packet sniffing
- 🧠 **ML-based anomaly detection** using a pretrained model
- 🔏 **Signature-based detection** for known attack patterns
- 🌐 **Threat intelligence enrichment** for flagged IPs/events
- 📝 **Persistent event logging** to a local database
- 📊 **Automated report generation**
- 🖥️ **Web dashboard** (Flask + HTML/CSS/JS templates)
- 📱 **Android app** for mobile monitoring
- 🧩 **Modular architecture** — each concern lives in its own module

---

## 🏗️ Architecture

```
              🌐 Live Network Traffic
                        │
                        ▼
              📦 sniffer.py (Packet Capture)
                        │
                        ▼
              🧠 detector.py (Core Detection Engine)
                        │
         ┌──────────────┴──────────────┐
         ▼                             ▼
🔏 Signature-Based Rules      🧬 ml_engine.py (Anomaly Model)
         │                             │
         └──────────────┬──────────────┘
                        ▼
              🌐 threat_intel.py (Enrichment)
                        │
                        ▼
              💾 database.py (Event Storage)
                        │
                        ▼
     📝 report_generator.py   🖥️ app.py (Dashboard / API)
```

---

## 📂 Project Structure

```
SENTRY-IDS/
├── app.py                    # Flask application entry point / web dashboard
├── config.py                 # Application configuration
├── database.py                # Database models and persistence layer
├── detector.py                # Core intrusion detection logic
├── ml_engine.py               # ML-based anomaly detection engine
├── ids_anomaly_model.pkl      # Pretrained anomaly detection model
├── sniffer.py                  # Live packet capture
├── threat_intel.py             # Threat intelligence lookups/enrichment
├── report_generator.py         # Automated report generation
├── templates/                   # HTML templates for the web dashboard
├── static/                       # CSS/JS/static assets for the dashboard
├── SENTRY_IDS.apk                # Companion Android application
├── IDS_Project_Report.pdf         # Detailed project report
└── requirements.txt                # Python dependencies
```

---

## ⚙️ Installation

**Prerequisites:** Python 3.10+, `pip`, and (on Linux) permissions to capture packets (root/`sudo` or `CAP_NET_RAW`).

```bash
# 1. Clone the repository
git clone https://github.com/kharedhruva-tech/SENTRY-IDS.git
cd SENTRY-IDS

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

By default the dashboard will be available at `http://localhost:5000`.

> ⚠️ Packet sniffing typically requires elevated privileges. On Linux/macOS you may need to run with `sudo`; on Windows, run your terminal as Administrator and ensure Npcap/WinPcap is installed.

---

## 📱 Android App

Prefer monitoring from your phone? Download the latest APK from the [Releases page](https://github.com/kharedhruva-tech/SENTRY-IDS/releases) or directly from the repo:

**[⬇️ Download SENTRY-IDS APK](https://github.com/kharedhruva-tech/SENTRY-IDS/raw/main/SENTRY_IDS.apk)**

> Since the APK isn't distributed via the Play Store, you'll need to enable **"Install from Unknown Sources"** in your Android device settings before installing.

---

## 🖥️ Usage

1. Start the server with `python app.py`.
2. Open the dashboard in your browser.
3. Start network monitoring — SENTRY-IDS begins capturing and analyzing live traffic.
4. Review real-time alerts as suspicious activity is detected.
5. Inspect logged events and generated reports for deeper investigation.
6. Use the Android app for alerts on the go.

---

## 💻 Technologies Used

| Layer | Technology |
|---|---|
| Language | Python |
| Web framework | Flask |
| Frontend | HTML, CSS, JavaScript |
| Data storage | SQLite |
| Packet capture | Scapy / raw sockets |
| Machine learning | Pretrained anomaly detection model (`ids_anomaly_model.pkl`) |
| Mobile | Android (APK) |

---

## 📈 Roadmap

- [ ] Deeper AI-powered anomaly detection
- [ ] Expanded threat intelligence integrations
- [ ] SIEM integration
- [ ] Email/webhook notifications for critical alerts
- [ ] Richer web dashboard visualizations
- [ ] Cloud-native deployment guide
- [ ] Automatic signature/rule updates
- [ ] Attack classification and severity scoring

---

## 🤝 Contributing

Contributions are welcome!

```bash
# 1. Fork the repository

# 2. Create a feature branch
git checkout -b feature/new-feature

# 3. Commit your changes
git commit -m "Add new feature"

# 4. Push to your fork
git push origin feature/new-feature

# 5. Open a Pull Request
```

## 🐞 Reporting Issues

Found a bug or have a feature request? [Open an issue](https://github.com/kharedhruva-tech/SENTRY-IDS/issues) and include:

- Operating system
- Python version
- Error message / stack trace
- Steps to reproduce

---

## 👨‍💻 Author

**Dhruva Khare**
*Cybersecurity Enthusiast — Network Security · Penetration Testing · SOC Operations · Threat Hunting · Digital Forensics*

[![GitHub](https://img.shields.io/badge/GitHub-kharedhruva--tech-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/kharedhruva-tech)

---

## 📄 License

This project is licensed under the **MIT License**.

---

<p align="center"><em>"Detect Early. Respond Faster. Stay Secure."</em><br>SENTRY-IDS — Protecting networks through intelligent intrusion detection.</p>
