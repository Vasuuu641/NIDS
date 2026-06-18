# What alerts.py needs to do : 
# 1. Accept alert data (attack type, source IP, etc)
# 2. Format a structured alert object
# 3. Output this to the console for now. Later on output logs for phase 3

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import logging

# Define the SEVERITY colors
SEVERITY_COLORS = {
    "LOW": "\033[92m",   # Green
    "MEDIUM": "\033[93m", # Yellow
    "HIGH": "\033[91m"    # Red
}
RESET_COLOR = "\033[0m"

# Ensure that logs exist and keep up with the current log file
Path("logs").mkdir(exist_ok=True)

_handler = logging.FileHandler("logs/alerts.log")
_handler.setFormatter(logging.Formatter("%(message)s"))

_logger = logging.getLogger("nids.alerts")
_logger.setLevel(logging.INFO)
_logger.addHandler(_handler)


# defining an alert data structure to hold the relevant information about detected attacks
@dataclass
class Alert:
    attack_type: str          # "ARP_SPOOF", "PORT_SCAN", "SYN_FLOOD"
    source_ip: str
    severity: str             # "LOW", "MEDIUM", "HIGH"
    message: str              # human-readable description
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    extra: dict = field(default_factory=dict)  # e.g. {"mac": "...", "ports_scanned": 42}

# dispatch function to handle alerts based on their severity
def dispatch_alert(alert: Alert):
    color = SEVERITY_COLORS.get(alert.severity, "")
    line = (
        f"[{alert.timestamp}] [{alert.severity}] "
        f"{alert.attack_type} | src: {alert.source_ip} | {alert.message}"
    )
    print(f"{color}{line}{RESET_COLOR}")  # print to console with color
    _logger.info(line)  # log file gets plain text, no ANSI codes