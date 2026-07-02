from pathlib import Path
import logging
from nids.alerts import Alert

# Ensure that logs exist and keep up with the current log file
Path("logs").mkdir(exist_ok=True)

_handler = logging.FileHandler("logs/alerts.log")
_handler.setFormatter(logging.Formatter("%(message)s"))

_logger = logging.getLogger("nids.storage")
_logger.setLevel(logging.INFO)
_logger.addHandler(_handler)

def save(alert: Alert) -> None:
    line = (
        f"[{alert.timestamp}] [{alert.severity}] "
        f"{alert.attack_type} | src: {alert.source_ip} | {alert.message}"
    )
    _logger.info(line)
    _handler.flush()