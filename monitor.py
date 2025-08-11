# monitor.py
import os
import psutil
import hashlib
import json
import socket
import smtplib
from email.mime.text import MIMEText

# Load config at module level
def load_config():
    with open("config.json", "r") as f:
        config = json.load(f)
    # Expand environment variables in monitored_paths
    config["monitored_paths"] = [os.path.expandvars(p) for p in config["monitored_paths"]]
    return config

config = load_config()

SAFE_PORTS = set(config["safe_ports"])
MONITORED_PATHS = config["monitored_paths"]
SUSPICIOUS_PROCESS_NAMES = [name.lower() for name in config["suspicious_process_names"]]
CPU_USAGE_THRESHOLD = config.get("cpu_usage_threshold", 80)
MEMORY_USAGE_THRESHOLD_MB = config.get("memory_usage_threshold_mb", 500)
SUSPICIOUS_IPS = set(config.get("suspicious_ips", []))
ENABLE_EMAIL_ALERTS = config.get("enable_email_alerts", False)
EMAIL_SETTINGS = config.get("email_settings", {})

file_hashes = {}

def is_admin():
    """
    Check if the script is running with admin/root privileges.
    Returns True if admin/root, False otherwise.
    """
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:  # Unix/Linux/Mac
        return os.geteuid() == 0

def get_file_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def check_file_changes():
    """
    Detect changes in monitored files.
    """
    global file_hashes
    events = []
    for path in MONITORED_PATHS:
        current_hash = get_file_hash(path)
        if path not in file_hashes:
            file_hashes[path] = current_hash
        elif file_hashes[path] != current_hash:
            events.append(f"File change detected: {path} (hash changed)")
            file_hashes[path] = current_hash
    return events

def check_suspicious_processes():
    """
    Detect suspicious process names and resource usage.
    """
    events = []
    for proc in psutil.process_iter(['name', 'cpu_percent', 'memory_info']):
        try:
            name = proc.info['name'].lower()
            if any(susp in name for susp in SUSPICIOUS_PROCESS_NAMES):
                events.append(f"[ALERT] Suspicious process detected: {name} (PID: {proc.pid})")
            # Resource usage alerts
            cpu = proc.cpu_percent(interval=0.1)
            mem_mb = proc.memory_info().rss / (1024 * 1024)
            if cpu > CPU_USAGE_THRESHOLD:
                events.append(f"[ALERT] High CPU usage: {name} (PID: {proc.pid}) using {cpu:.1f}% CPU")
            if mem_mb > MEMORY_USAGE_THRESHOLD_MB:
                events.append(f"[ALERT] High memory usage: {name} (PID: {proc.pid}) using {mem_mb:.1f} MB RAM")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return events

def get_process_name(pid):
    try:
        return psutil.Process(pid).name()
    except Exception:
        return "Unknown"

def check_open_ports_advanced():
    """
    Scan for open TCP ports, associate with processes, and check against whitelist.
    """
    events = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN:
            port = conn.laddr.port
            pid = conn.pid if conn.pid else 0
            proc_name = get_process_name(pid)
            whitelisted = port in SAFE_PORTS
            if whitelisted:
                events.append(f"Open TCP port {port} (Process: {proc_name}, PID: {pid}) [SAFE]")
            else:
                events.append(f"[ALERT] Suspicious open port {port} (Process: {proc_name}, PID: {pid}) [NOT WHITELISTED]")
    return events

def check_suspicious_outbound_connections():
    """
    Alert if there are outbound connections to suspicious IPs.
    """
    events = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
            remote_ip = conn.raddr.ip
            pid = conn.pid if conn.pid else 0
            proc_name = get_process_name(pid)
            if remote_ip in SUSPICIOUS_IPS:
                events.append(f"[ALERT] Outbound connection to suspicious IP {remote_ip} by {proc_name} (PID: {pid})")
    return events

def send_email_alert(subject, body):
    """
    Send an email alert using the settings in config.json.
    """
    if not ENABLE_EMAIL_ALERTS:
        return
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_SETTINGS['from_addr']
        msg['To'] = EMAIL_SETTINGS['to_addr']

        with smtplib.SMTP(EMAIL_SETTINGS['smtp_server'], EMAIL_SETTINGS['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_SETTINGS['username'], EMAIL_SETTINGS['password'])
            server.sendmail(EMAIL_SETTINGS['from_addr'], [EMAIL_SETTINGS['to_addr']], msg.as_string())
    except Exception as e:
        from logger import log_event
        log_event(f"Failed to send email alert: {e}", level="ERROR")

def check_security_events():
    """
    Run all security checks and return a list of event strings.
    """
    events = []
    events.extend(check_suspicious_processes())
    events.extend(check_open_ports_advanced())
    events.extend(check_file_changes())
    events.extend(check_suspicious_outbound_connections())
    return events
