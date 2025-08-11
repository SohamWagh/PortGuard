# Security Monitor

A cross-platform (Windows/Linux) Python security monitoring tool for detecting suspicious processes, file changes, open ports, and more. All configuration is handled via a simple `config.json` file.

---

## Features

- Detects suspicious processes by name and resource usage (CPU/memory)
- Monitors specified files for unauthorized changes
- Scans open TCP ports, associates them with processes, and checks against a whitelist
- Alerts on suspicious outbound network connections
- Logs all events with timestamps and log rotation
- Optional email notifications for critical alerts
- Fully configurable via `config.json`
- Designed for both Windows and Linux

---

## Setup

1. **Install Python 3.7+** (if not already installed)

2. **Install dependencies:**
   ```sh
   pip install psutil
   ```

3. **Place all files in the same folder:**
   - `main.py`
   - `monitor.py`
   - `logger.py`
   - `config.json`

4. **Edit `config.json`** to match your environment:
   - Set files to monitor, safe ports, suspicious process names, etc.
   - If you want email alerts, set `"enable_email_alerts": true` and fill in your SMTP/email details.

---

## Usage

### Windows

1. Open Command Prompt as Administrator (right-click > "Run as administrator")
2. Navigate to the project folder:
   ```sh
   cd C:\Security_monitor
   ```
3. Run:
   ```sh
   python main.py
   ```

### Linux

1. Open a terminal
2. Navigate to the project folder
3. Run:
   ```sh
   sudo python3 main.py
   ```

---

## Configuration

All settings are in `config.json`:

| Field                      | Description                                      |
|----------------------------|--------------------------------------------------|
| `monitored_paths`          | List of files to watch for changes               |
| `safe_ports`               | List of allowed TCP ports                        |
| `suspicious_process_names` | List of keywords for suspicious processes        |
| `log_file`                 | Log file name                                    |
| `monitor_interval_seconds` | How often to scan (seconds)                      |
| `cpu_usage_threshold`      | CPU % threshold for alerts                       |
| `memory_usage_threshold_mb`| Memory (MB) threshold for alerts                 |
| `enable_email_alerts`      | true/false for email alerts                      |
| `email_settings`           | Your SMTP/email info (if using email alerts)     |
| `suspicious_ips`           | List of IPs to flag outbound connections         |

---

## Log Files

- All events are logged to the file specified in `config.json` (default: `security_log.txt`)
- Log files are rotated automatically when they reach the configured size

---

## Troubleshooting

- If you see Unicode errors, remove emojis or non-ASCII characters from log messages.
- If you get permission errors, make sure you are running as administrator/root.
- For email alerts, ensure your SMTP settings are correct and less secure app access is enabled if needed.

---

## License

MIT License 

---

## Author

Soham Wagh 