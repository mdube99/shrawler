"""Incremental, crash-tolerant scan persistence."""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


class ScanStateStore:
    """Append events immediately and publish atomic resumable checkpoints."""

    def __init__(self, root: Path, enabled: bool = True) -> None:
        self.root = root
        self.enabled = enabled
        self.events_path = root / "scan-events.jsonl"
        self.state_path = root / "scan-state.json"
        self._lock = threading.Lock()
        if enabled:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def append(self, event: str, **data: Any) -> None:
        if not self.enabled:
            return
        record = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **data,
        }
        encoded = json.dumps(record, separators=(",", ":")) + "\n"
        with self._lock, self.events_path.open("a", encoding="utf-8") as handle:
            os.chmod(self.events_path, 0o600)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())

    def checkpoint(self, results: Dict[str, Any], summary: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        payload = {"results": results, "summary": summary}
        temporary = self.root / ".scan-state.json.tmp"
        with self._lock, temporary.open("w", encoding="utf-8") as handle:
            os.chmod(temporary, 0o600)
            json.dump(payload, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.state_path)

    def load(self) -> Dict[str, Any]:
        if not self.enabled or not self.state_path.exists():
            return {}
        with self.state_path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, dict) else {}
