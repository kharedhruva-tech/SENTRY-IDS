from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, send_file, g
from functools import wraps
import json
import queue
import time
from datetime import datetime
from config import Config
from database import db, init_db, User, PacketLog, Alert, BlacklistIP
from sniffer import IntrusionDetectionSniffer
from threat_intel import geo_service
from ml_engine import ml_engine
from report_generator import ReportGenerator
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
init_db(app)

# ML Engine startup initialization
with app.app_context():
    ml_engine.load_model()

# SSE clients list
active_sse_clients = []

def broadcast_sse(event_type, data):
    """Sends JSON-encoded events to all listening dashboard browser clients."""
    event_str = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    for client_queue in list(active_sse_clients):
        try:
            client_queue.put_nowait(event_str)
        except queue.Full:
            pass

# Initialize and start network sniffer/simulator
sniffer = IntrusionDetectionSniffer(app)
sniffer.set_callbacks(
    on_packet=lambda p: broadcast_sse("packet", p),
    on_alert=lambda a: broadcast_sse("alert", a)
)
sniffer.start()

# ==========================================
# AUTHENTICATION DECORATORS & LOGGED IN USER
# ==========================================
class AnonymousUser:
    is_authenticated = False
    username = "Anonymous"
    role = "Viewer"

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = AnonymousUser()
    else:
        user = db.session.get(User, user_id)
        if user:
            user.is_authenticated = True
            g.user = user
        else:
            session.clear()
            g.user = AnonymousUser()

@app.context_processor
def inject_user():
    return dict(current_user=g.user)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user.is_authenticated:
            flash("Console authentication required.", "error")
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not g.user.is_authenticated:
                return redirect(url_for('login_page'))
            if g.user.role not in roles:
                flash("Access denied: Insufficient console authorization levels.", "error")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==========================================
# AUTHENTICATION PATHS
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f"Operator {username} authenticated successfully.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid operator credentials. Access denied.", "error")
            
    return render_template('login.html')

@app.route('/login-page')
def login_page():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        
        # Check if username is taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Operator username is already registered in the system.", "error")
            return render_template('register.html')
            
        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash("Operator console credentials configured successfully. You may log in.", "success")
        return redirect(url_for('login_page'))
        
    return render_template('register.html')

@app.route('/register-page')
def register_page():
    return render_template('register.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash("Console session terminated.", "success")
    return redirect(url_for('login_page'))

# ==========================================
# DASHBOARD PAGES
# ==========================================
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch recent stats from database
    total_packets = PacketLog.query.count()
    total_alerts = Alert.query.count()
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    recent_packets = PacketLog.query.order_by(PacketLog.timestamp.desc()).limit(10).all()
    
    return render_template(
        'dashboard.html',
        total_packets=total_packets,
        total_alerts=total_alerts,
        recent_alerts=recent_alerts,
        recent_packets=recent_packets,
        active_menu='dashboard'
    )

@app.route('/alerts')
@login_required
def alerts_page():
    severity = request.args.get('severity', '')
    category = request.args.get('category', '')
    
    query = Alert.query
    if severity:
        query = query.filter_by(severity=severity)
    if category:
        query = query.filter_by(category=category)
        
    alerts = query.order_by(Alert.timestamp.desc()).all()
    
    # Fetch categories for filtering dropdown list
    categories_db = db.session.query(Alert.category).distinct().all()
    unique_categories = [c[0] for c in categories_db]
    
    return render_template(
        'alerts.html',
        alerts=alerts,
        total_alerts=len(alerts),
        selected_severity=severity,
        selected_category=category,
        unique_categories=unique_categories,
        active_menu='alerts'
    )

@app.route('/logs')
@login_required
def logs_page():
    ip = request.args.get('ip', '')
    protocol = request.args.get('protocol', '')
    
    query = PacketLog.query
    if ip:
        query = query.filter((PacketLog.src_ip == ip) | (PacketLog.dst_ip == ip))
    if protocol:
        query = query.filter_by(protocol=protocol)
        
    packets = query.order_by(PacketLog.timestamp.desc()).limit(100).all()
    
    return render_template(
        'logs.html',
        packets=packets,
        selected_ip=ip,
        selected_proto=protocol,
        active_menu='logs'
    )

@app.route('/settings')
@login_required
def settings_page():
    blacklist = BlacklistIP.query.order_by(BlacklistIP.added_at.desc()).all()
    return render_template(
        'settings.html',
        blacklist=blacklist,
        active_menu='settings'
    )

# ==========================================
# SYSTEM API ENDPOINTS
# ==========================================
@app.route('/api/live-stream')
@login_required
def live_stream():
    """Server-Sent Events streaming handler for browser dashboard clients."""
    def event_generator():
        q = queue.Queue(maxsize=200)
        active_sse_clients.append(q)
        try:
            # Send initial state/status message
            status_tag = sniffer.status
            yield f"event: status\ndata: {json.dumps({'status': status_tag})}\n\n"
            
            while True:
                try:
                    event_data = q.get(timeout=15.0)
                    yield event_data
                except queue.Empty:
                    # Keep-alive signal to prevent timeout disconnects
                    yield ": keep-alive\n\n"
        finally:
            if q in active_sse_clients:
                active_sse_clients.remove(q)
                
    return Response(event_generator(), mimetype='text/event-stream')

@app.route('/api/stats-summary')
@login_required
def stats_summary():
    """Generates counts by severity level and targets for dashboard ChartJS views."""
    # Severity distributions
    sev_tuples = db.session.query(Alert.severity, db.func.count(Alert.id)).group_by(Alert.severity).all()
    severity_counts = {t[0]: t[1] for t in sev_tuples}
    
    # Targeted Ports distribution
    port_tuples = db.session.query(PacketLog.dst_port, db.func.count(PacketLog.id))\
        .filter(PacketLog.classification != 'Normal')\
        .group_by(PacketLog.dst_port)\
        .order_by(db.func.count(PacketLog.id).desc())\
        .limit(5).all()
    
    # Format: [[port, count], ...]
    top_ports = [[p[0], p[1]] for p in port_tuples if p[0] is not None]
    
    return {
        "severity_counts": severity_counts,
        "top_ports": top_ports
    }

@app.route('/api/alert/<int:alert_id>')
@login_required
def alert_detail(alert_id):
    """Retrieve detailed alert attributes along with cached/resolved IP Geolocation."""
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return {"error": "Alert not found"}, 404
        
    geo = geo_service.get_location(alert.src_ip)
    
    return {
        "id": alert.id,
        "timestamp": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "category": alert.category,
        "severity": alert.severity,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "message": alert.message,
        "status": alert.status,
        "is_ml": alert.is_ml,
        "confidence": alert.confidence,
        "geolocation": geo
    }

@app.route('/api/alert/<int:alert_id>/update-status', methods=['POST'])
@login_required
@role_required(['Admin', 'Analyst'])
def update_alert_status(alert_id):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        flash("Alert not found.", "error")
        return redirect(url_for('alerts_page'))
        
    new_status = request.form.get('status')
    if new_status in ['Active', 'Resolved', 'Muted']:
        alert.status = new_status
        db.session.commit()
        flash(f"Incident #{alert_id} status updated to {new_status}.", "success")
    return redirect(url_for('alerts_page'))

@app.route('/api/ml/train', methods=['POST'])
@login_required
@role_required(['Admin'])
def retrain_model():
    """Extracts historical packet metrics from database and retrains IsolationForest."""
    try:
        # Load packets logs to train
        logs = PacketLog.query.all()
        if len(logs) < 100:
            # Fall back to self-training synthesis if database is small
            ml_engine.train_model()
        else:
            # Map database records to model input lists
            data_samples = []
            for log in logs:
                proto_code = ml_engine.protocol_map.get(log.protocol.upper(), 0)
                entropy = ml_engine.calculate_entropy(log.payload_summary)
                data_samples.append([
                    proto_code,
                    log.src_port or 0,
                    log.dst_port or 0,
                    log.length or 0,
                    3.0,  # rate approx
                    entropy
                ])
            ml_engine.train_model(data_samples)
            
        return {"status": "success", "message": "Machine learning anomaly detection model retrained."}
    except Exception as e:
        return {"status": "error", "message": f"ML Training failed: {e}"}, 500

@app.route('/settings/blacklist/add', methods=['POST'])
@login_required
@role_required(['Admin', 'Analyst'])
def add_blacklist():
    ip = request.form.get('ip_address')
    desc = request.form.get('description', 'Blocked manually')
    
    if ip:
        # Check if already exists
        exists = BlacklistIP.query.filter_by(ip_address=ip).first()
        if not exists:
            blocked = BlacklistIP(ip_address=ip, description=desc)
            db.session.add(blocked)
            db.session.commit()
            flash(f"IP {ip} blacklisted and blocked.", "success")
        else:
            flash(f"IP {ip} is already registered in the blacklist.", "error")
            
    return redirect(url_for('settings_page'))

@app.route('/settings/blacklist/delete/<int:ip_id>', methods=['POST'])
@login_required
@role_required(['Admin', 'Analyst'])
def delete_blacklist(ip_id):
    ip_rec = db.session.get(BlacklistIP, ip_id)
    if ip_rec:
        db.session.delete(ip_rec)
        db.session.commit()
        flash(f"IP {ip_rec.ip_address} has been unblocked.", "success")
    return redirect(url_for('settings_page'))

@app.route('/reports/download/<string:file_type>')
@login_required
def download_report(file_type):
    # Fetch alerts for report
    alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    
    # Calculate stats
    stats = {
        "total_alerts": len(alerts),
        "critical_alerts": sum(1 for a in alerts if a.severity == 'Critical'),
        "high_alerts": sum(1 for a in alerts if a.severity == 'High'),
        "other_alerts": sum(1 for a in alerts if a.severity in ['Medium', 'Low'])
    }
    
    if file_type == 'csv':
        csv_data = ReportGenerator.generate_csv_report(alerts)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=sentry_ids_report.csv"}
        )
    elif file_type == 'pdf':
        pdf_data = ReportGenerator.generate_pdf_report(alerts, stats)
        return Response(
            pdf_data,
            mimetype="application/pdf",
            headers={"Content-disposition": f"attachment; filename=sentry_ids_report_{int(time.time())}.pdf"}
        )
        
    return "Invalid File Type", 400

if __name__ == '__main__':
    # Run the server locally on port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)
