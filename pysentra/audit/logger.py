from datetime import datetime, timezone

class AuditLogger:
    def __init__(self): self.entries = []
    def log(self, method, url, module):
        self.entries.append({"timestamp": datetime.now(timezone.utc).isoformat(), "method": method, "url": url, "module": module})
