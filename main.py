# main.py
import monitor
from logger import setup_logger, log_event
import time
import sys
import json

def main():
    # Load config
    with open("config.json", "r") as f:
        config = json.load(f)

    # Setup logger
    setup_logger(
        log_file=config["log_file"],
        log_level=config.get("log_level", "INFO"),
        max_bytes=config.get("log_max_bytes", 1048576),
        backup_count=config.get("log_backup_count", 3)
    )

    log_event("Security Monitor is starting...", level="INFO")
    print("Security Monitor is starting...")

    # Privilege check
    if not monitor.is_admin():
        log_event("[ERROR] This script must be run as administrator/root to access all ports and process info.", level="ERROR")
        print("[ERROR] This script must be run as administrator/root to access all ports and process info.")
        print("Windows: Run as Administrator\nLinux: Use sudo")
        sys.exit(1)

    try:
        alert_count = 0
        while True:
            events = monitor.check_security_events()
            if events:
                for event in events:
                    # Determine log level
                    level = "CRITICAL" if "[ALERT]" in event else "INFO"
                    log_event(event, level=level)
                    print(f"[{level}] {event}")
                    if "[ALERT]" in event:
                        alert_count += 1
                        # Email notification for critical alerts
                        if monitor.ENABLE_EMAIL_ALERTS:
                            monitor.send_email_alert("Security Monitor Alert", event)
            else:
                log_event("No suspicious activity detected.", level="INFO")
                print("[INFO] No suspicious activity detected.")
            time.sleep(config.get("monitor_interval_seconds", 5))
    except KeyboardInterrupt:
        log_event("🛑 Security Monitor stopped by user.", level="WARNING")
        print("\n🛑 Security Monitor stopped by user.")
        print(f"Total alerts detected in this session: {alert_count}")

if __name__ == "__main__":
    main()

