try:
    from flask_sqlalchemy import SQLAlchemy
except Exception:
    # Provide a clear error at runtime and a simple stub so editors/linters
    # that can't resolve the import won't break parsing of this file.
    class SQLAlchemy:  # minimal stub
        def __init__(self, *args, **kwargs):
            raise RuntimeError("flask_sqlalchemy is required. Install it with: pip install flask_sqlalchemy")
from datetime import datetime
from werkzeug.security import generate_password_hash
import os

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='Viewer', nullable=False)  # Admin, Analyst, Viewer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

class PacketLog(db.Model):
    __tablename__ = 'packet_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    src_ip = db.Column(db.String(45), nullable=False, index=True)
    dst_ip = db.Column(db.String(45), nullable=False, index=True)
    protocol = db.Column(db.String(10), nullable=False)
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    length = db.Column(db.Integer)
    payload_summary = db.Column(db.Text)
    classification = db.Column(db.String(50), default='Normal')  # Normal or Anomaly

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    category = db.Column(db.String(50), nullable=False)  # e.g., Port Scan, DDoS, SQL Injection, etc.
    severity = db.Column(db.String(20), nullable=False)   # Low, Medium, High, Critical
    src_ip = db.Column(db.String(45), nullable=False)
    dst_ip = db.Column(db.String(45), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Active')   # Active, Resolved, Muted
    is_ml = db.Column(db.Boolean, default=False)
    confidence = db.Column(db.Float, default=1.0)

class BlacklistIP(db.Model):
    __tablename__ = 'blacklist_ips'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    description = db.Column(db.String(255))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

def init_db(app):
    db.init_app(app)
    with app.app_context():
        # SQLite can fail with: "database is locked" if another thread/process
        # is holding the DB while the app starts.
        try:
            db.create_all()

            # Check if users already exist
            if User.query.first() is None:
                # Seed default users
                admin = User(username='admin', role='Admin')
                admin.set_password('admin123')

                analyst = User(username='analyst', role='Analyst')
                analyst.set_password('analyst123')

                viewer = User(username='viewer', role='Viewer')
                viewer.set_password('viewer123')

                db.session.add_all([admin, analyst, viewer])

            # Check if blacklist already exists
            if BlacklistIP.query.first() is None:
                # Seed default blacklisted IPs for threat intelligence
                blacklist_seeds = [
                    BlacklistIP(ip_address='198.51.100.42', description='Botnet Command & Control Server'),
                    BlacklistIP(ip_address='203.0.113.88', description='Known Tor Exit Node (Hostile Scanner)'),
                    BlacklistIP(ip_address='192.0.2.144', description='Brute Force Attack Source'),
                    BlacklistIP(ip_address='185.220.101.5', description='Malicious Proxy Server')
                ]
                db.session.add_all(blacklist_seeds)

            db.session.commit()

        except Exception:
            # Ensure session doesn't remain in a broken/locked state.
            db.session.rollback()
            raise
