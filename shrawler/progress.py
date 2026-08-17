"""Low-noise interactive scan progress."""

import sys
import threading
import time
from typing import Any


class ProgressReporter:
    def __init__(self, crawler: Any, interval: float = 0.2) -> None:
        self.crawler = crawler
        self.interval = interval
        self.started = time.monotonic()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._width = 0

    def start(self) -> None:
        self._thread.start()

    def _line(self) -> str:
        with self.crawler._state_lock:
            hosts = len([key for key in self.crawler.scan_results if not key.startswith("_")])
            shares = sum(
                len(value.get("shares", {}))
                for key, value in self.crawler.scan_results.items()
                if not key.startswith("_") and isinstance(value, dict)
            )
            files = self.crawler.files_seen_count
            matches = len(self.crawler.snaffler_matches)
            downloaded = self.crawler.downloaded_bytes
        elapsed = int(time.monotonic() - self.started)
        return (
            f"Scanning | {hosts} hosts | {shares} shares | {files:,} files | "
            f"{matches:,} matches | {downloaded / 1024**2:.1f} MiB downloaded | "
            f"{elapsed // 60:02d}:{elapsed % 60:02d}"
        )

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            line = self._line()
            self._width = max(self._width, len(line))
            print("\r" + line.ljust(self._width), end="", file=sys.stderr, flush=True)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1)
        if self._width:
            print("\r" + " " * self._width + "\r", end="", file=sys.stderr, flush=True)
