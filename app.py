import os
import sys
import time
import ipaddress
import platform
import subprocess
from flask import Flask, render_template, jsonify, request, session, redirect, url_for

# Production Configuration
from config import (
    NETWORK_INTERFACE, SCAN_SUBNET, SYSTEM_MODE, LOG_FILE, 
    ADMIN_USER, ADMIN_PASS, SECRET_KEY, REFRESH_INTERVAL, 
    IS_LINUX, REQUIRED_TOOLS, HISTORY_LIMIT
)
from traffic_control import tc_manager
from logger import logger, log_action, log_error
from scanner import scanner
from ai_engine import ai_engine
from reports import report_gen

# --- PRODUCTION HARDENING (Phase 9) ---
def check_environment():
    """Verifies root privileges and required tools."""
    if IS_LINUX:
        # Check Root
        if os.geteuid() != 0:
            print("CRITICAL: This application MUST be run with sudo/root privileges for network control.")
            sys.exit(1)
        
        # Check Dependencies
        for tool in REQUIRED_TOOLS:
            try:
                if subprocess.run(["which", tool], capture_output=True).returncode != 0:
                    log_error(f"DEPENDENCY_MISSING: {tool} is not installed.")
                    print(f"CRITICAL: Missing required tool: {tool}")
                    sys.exit(1)
            except Exception:
                sys.exit(1)
    
    log_action("SYSTEM_STARTUP", "Environment verification successful.")

check_environment()
# --------------------------------------

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Application State
current_mode = SYSTEM_MODE
users_db = scanner.devices
usage_history = {user['ip']: [] for user in users_db}


def _sync_history_keys(devices):
    for device in devices:
        ip = device.get('ip')
        if ip and ip not in usage_history:
            usage_history[ip] = []


def _infer_topology(devices):
    active_devices = [device for device in devices if device.get('ip')]
    if not active_devices:
        return {
            "topology": "Unknown",
            "summary": "No connected devices found",
            "nodes": [],
            "links": []
        }

    subnet_groups = {}
    for device in active_devices:
        ip = device['ip']
        subnet_key = '.'.join(ip.split('.')[:3]) if ip.count('.') == 3 else 'unknown'
        subnet_groups.setdefault(subnet_key, []).append(ip)

    if len(subnet_groups) == 1:
        topology_name = "Star"
        summary = "Single subnet with central router/switch behavior"
    else:
        topology_name = "Tree/Hybrid"
        summary = "Multiple subnet segments detected"

    nodes = [{"id": "router", "label": "Router/Gateway", "type": "Core"}]
    links = []
    for device in active_devices:
        nodes.append({
            "id": device['ip'],
            "label": device.get('name', device['ip']),
            "type": device.get('device_type', 'Unknown')
        })
        links.append({"from": "router", "to": device['ip']})

    return {
        "topology": topology_name,
        "summary": summary,
        "subnet_count": len(subnet_groups),
        "nodes": nodes,
        "links": links
    }

def is_authenticated():
    return session.get('logged_in')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USER and password == ADMIN_PASS:
            session['logged_in'] = True
            log_action("AUTH", "Admin logged in successfully")
            return redirect(url_for('index'))
        else:
            log_error("AUTH_FAILURE: Invalid attempt")
            return render_template('login.html', error="Invalid Credentials")
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    log_action("AUTH", "Admin logged out")
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not is_authenticated():
        return redirect(url_for('login'))
    return render_template('index.html', os_type=platform.system())

@app.route('/api/status')
def get_status():
    if not is_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    global users_db, current_mode
    
    # Active Guard Logic (Phase 9)
    if current_mode == "AUTO":
        fresh_scanner_devices = scanner.update_device_list()
        for dev in fresh_scanner_devices:
            # Auto-block loop (Industry Security)
            # If status isn't explicitly ACTIVE/ADMIN etc, and it's a new discovery
            if dev.get('role') == 'Guest' and dev.get('status') != 'ACTIVE':
                 # Treat as UNKNOWN/Potential Intruder in high-security mode
                 pass 
        users_db = fresh_scanner_devices

    _sync_history_keys(users_db)

    device_by_ip = {device.get('ip'): device for device in users_db}
        
    current_usage = tc_manager.get_realtime_usage(users_db)
    for usage_item in current_usage:
        matched = device_by_ip.get(usage_item.get('ip'), {})
        usage_item['device_type'] = matched.get('device_type', 'Unknown')
        usage_item['name'] = matched.get('name', usage_item.get('name', 'Unknown'))
    current_time = time.strftime("%H:%M:%S")
    
    predictions = {}
    anomalies = {}
    for item in current_usage:
        ip = item['ip']
        if ip not in usage_history:
            usage_history[ip] = []
        usage_history[ip].append({"time": current_time, "val": item['usage']})
        
        ai_engine.add_data_point(ip, item['usage'])
        predictions[ip] = ai_engine.predict_next(ip)
        anomalies[ip] = ai_engine.detect_anomaly(ip, item['usage'])
        
        if len(usage_history[ip]) > HISTORY_LIMIT:
            usage_history[ip].pop(0)
    
    health = ai_engine.get_network_health(current_usage)
            
    return jsonify({
        "users": current_usage,
        "history": usage_history,
        "mode": current_mode,
        "predictions": predictions,
        "anomalies": anomalies,
        "health": health,
        "topology": _infer_topology(users_db)
    })


@app.route('/api/scan', methods=['POST'])
def run_scan():
    if not is_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    global users_db
    data = request.get_json(silent=True) or {}
    manual_ip = (data.get('manual_ip') or '').strip()

    if manual_ip:
        result = scanner.add_or_update_manual_ip(manual_ip)
        if result.get('status') != 'success':
            return jsonify(result), 400
        users_db = scanner.devices
        _sync_history_keys(users_db)
        log_action("MANUAL_IP_SCAN", f"Checked manual IP: {manual_ip} reachable={result.get('reachable')}")
        return jsonify({
            "status": "success",
            "message": result.get('message'),
            "reachable": result.get('reachable'),
            "device": result.get('device'),
            "devices": users_db
        })

    users_db = scanner.update_device_list()
    _sync_history_keys(users_db)
    log_action("AUTO_SCAN", f"Auto scan completed. Devices: {len(users_db)}")
    return jsonify({"status": "success", "devices": users_db})


@app.route('/api/manual_ip', methods=['POST'])
def manual_ip_scan():
    if not is_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    global users_db
    data = request.get_json(silent=True) or {}
    manual_ip = (data.get('ip') or '').strip()

    result = scanner.add_or_update_manual_ip(manual_ip)
    if result.get('status') != 'success':
        return jsonify(result), 400

    users_db = scanner.devices
    _sync_history_keys(users_db)
    log_action("MANUAL_IP_SCAN", f"Checked manual IP: {manual_ip} reachable={result.get('reachable')}")
    return jsonify({
        "status": "success",
        "message": result.get('message'),
        "reachable": result.get('reachable'),
        "device": result.get('device'),
        "devices": users_db
    })


@app.route('/api/device/<ip>/details', methods=['GET'])
def get_device_details(ip):
    if not is_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    target_device = next((device for device in users_db if device.get('ip') == ip), None)
    if not target_device:
        return jsonify({"status": "error", "message": "Device not found"}), 404

    current_usage = tc_manager.get_realtime_usage(users_db)
    target_usage = next((entry for entry in current_usage if entry.get('ip') == ip), None)
    if not target_usage:
        return jsonify({"status": "error", "message": "Usage data unavailable"}), 404

    total_usage = sum(max(0.0, entry.get('usage', 0.0)) for entry in current_usage) or 1.0
    total_limit = sum(max(0.0, entry.get('limit', 0.0)) for entry in current_usage) or 1.0
    prediction = ai_engine.predict_next(ip)

    usage_share_percent = round((target_usage.get('usage', 0.0) / total_usage) * 100, 2)
    limit_share_percent = round((target_usage.get('limit', 0.0) / total_limit) * 100, 2)

    return jsonify({
        "status": "success",
        "device": {
            "ip": ip,
            "name": target_device.get('name', 'Unknown'),
            "mac": target_device.get('mac', '00:00:00:00:00:00'),
            "device_type": target_device.get('device_type', 'Unknown'),
            "role": target_device.get('role', 'Guest'),
            "status": target_device.get('status', 'ACTIVE')
        },
        "network_division": {
            "current_usage_mbps": round(target_usage.get('usage', 0.0), 2),
            "allocated_limit_mbps": round(target_usage.get('limit', 0.0), 2),
            "predicted_next_mbps": round(prediction, 2),
            "usage_share_percent": usage_share_percent,
            "limit_share_percent": limit_share_percent
        },
        "history": usage_history.get(ip, [])[-15:]
    })


@app.route('/api/topology', methods=['GET'])
def get_topology():
    if not is_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    return jsonify({"status": "success", "data": _infer_topology(users_db)})

@app.route('/api/set_mode', methods=['POST'])
def set_mode():
    if not is_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    global current_mode
    data = request.json
    new_mode = data.get('mode')
    if new_mode in ["MANUAL", "AUTO"]:
        current_mode = new_mode
        log_action("SYSTEM_MODE", f"Switched to {new_mode}")
        return jsonify({"status": "success", "mode": current_mode})
    return jsonify({"status": "error", "message": "Invalid mode"}), 400

@app.route('/api/generate_report', methods=['POST'])
def generate_report():
    if not is_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    report_path = report_gen.generate_csv_report(usage_history)
    log_action("REPORT", f"Generated: {report_path}")
    return jsonify({"status": "success", "file": report_path})

@app.route('/api/block', methods=['POST'])
@app.route('/api/unblock', methods=['POST'])
def handle_security_action():
    if not is_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    ip = request.json.get('ip')
    action = request.path.split('/')[-1]
    
    success = False
    if action == 'block':
        success = tc_manager.block_ip(ip)
        status_target = 'BLOCKED'
    else:
        success = tc_manager.unblock_ip(ip)
        status_target = 'ACTIVE'
        
    if success:
        for user in users_db:
            if user['ip'] == ip:
                user['status'] = status_target
        scanner.save_devices()
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 500

@app.route('/api/update_priority', methods=['POST'])
def update_priority():
    if not is_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    data = request.json
    ip = data.get('ip')
    new_role = data.get('priority') # Mapped to role in frontend
    
    # Priority to Mbps mapping
    priority_map = {"Admin": 100, "Teacher": 50, "Student": 10, "Guest": 5}
    
    if new_role not in priority_map:
        return jsonify({"status": "error", "message": "Invalid Role"}), 400

    for user in users_db:
        if user['ip'] == ip:
            user['role'] = new_role
            user['bandwidth_limit'] = priority_map[new_role]
            scanner.save_devices()
            
            classid = ip.split('.')[-1]
            tc_manager.set_limit(ip, user['bandwidth_limit'], classid, role=new_role)
            log_action("PRIORITY_UPDATE", f"{ip} -> {new_role}")
            return jsonify({"status": "success"})
            
    return jsonify({"status": "error", "message": "IP not found"}), 404

@app.route('/api/predict', methods=['GET'])
def predict_usage():
    """API endpoint for external predictions."""
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "IP required"}), 400
    
    prediction = ai_engine.predict_next(ip)
    anomaly = ai_engine.detect_anomaly(ip, 0)  # Placeholder, would need current usage
    return jsonify({"ip": ip, "prediction": prediction, "anomaly": anomaly})


@app.route('/devices')
def devices_plain():
    if not is_authenticated():
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    return jsonify(users_db)

if __name__ == '__main__':
    logger.info(f"SmartNet Production Engine active on {platform.node()}")
    app.run(host='0.0.0.0', port=5000)
