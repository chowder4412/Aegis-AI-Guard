from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from threading import Lock
from typing import Any


@dataclass
class RouteStats:
    count: int = 0
    errors: int = 0
    total_duration_ms: float = 0.0


class TelemetryStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: dict[str, int] = defaultdict(int)
        self._routes: dict[str, RouteStats] = defaultdict(RouteStats)

    def increment(self, metric: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[metric] += amount

    def record_request(self, path: str, status_code: int, duration_ms: float) -> None:
        with self._lock:
            route = self._routes[path]
            route.count += 1
            route.total_duration_ms += max(duration_ms, 0.0)
            if status_code >= 400:
                route.errors += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            counters = dict(self._counters)
            routes = {
                path: {
                    "count": stats.count,
                    "errors": stats.errors,
                    "error_rate": round((stats.errors / stats.count), 4) if stats.count else 0.0,
                    "avg_duration_ms": round((stats.total_duration_ms / stats.count), 2) if stats.count else 0.0,
                }
                for path, stats in self._routes.items()
            }
        return {"counters": counters, "routes": routes}
