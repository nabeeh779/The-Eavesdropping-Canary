import logging
from datetime import datetime

'''I have made it using AI'''


class CanaryLogger:
    def __init__(self, log_file="canary_alerts.log"):
        logging.basicConfig(
            filename=log_file,
            format='%(asctime)s - %(message)s',
            level=logging.WARNING
        )
        self.logger = logging.getLogger("CanaryDetector")

    def log_alert(self, src, sport, dst, dport, payload=""):
        """Log suspicious connection with key details"""
        msg = f"SUSPICIOUS: {src}:{sport} -> {dst}:{dport}"
        if payload:
            msg += f" | Payload: {payload[:100]}..."
        self.logger.warning(msg)

