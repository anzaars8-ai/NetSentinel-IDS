"""Track traffic statistics per source IP."""

import time


class SourceStats:

    __slots__ = (
        "packets",
        "bytes_total",
        "unique_ports",
        "syns",
    )

    def __init__(self):
        self.packets = 0
        self.bytes_total = 0
        self.unique_ports = set()
        self.syns = 0


class FlowTracker:

    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self.sources = {}
        self.last_seen = {}

        self.total_packets = 0
        self.total_bytes = 0

    def update(self, pkt: dict):

        now = time.time()

        self._expire(now)

        src = pkt["src_ip"]

        stats = self.sources.setdefault(
            src,
            SourceStats()
        )

        self.last_seen[src] = now

        stats.packets += 1
        stats.bytes_total += pkt["length"]

        self.total_packets += 1
        self.total_bytes += pkt["length"]

        if pkt["dst_port"] is not None:

            stats.unique_ports.add(
                pkt["dst_port"]
            )

            if (
                pkt["proto"] == "TCP"
                and "S" in pkt["flags"]
                and "A" not in pkt["flags"]
            ):
                stats.syns += 1

    def _expire(self, now):

        stale = [
            src
            for src, timestamp in self.last_seen.items()
            if now - timestamp > self.window
        ]

        for src in stale:

            self.sources.pop(src, None)
            self.last_seen.pop(src, None)

    def stats_for(self, src):

        return self.sources.get(
            src
        ) or SourceStats()

    def snapshot(self):

        return {
            "active_sources": len(self.sources),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
        }
