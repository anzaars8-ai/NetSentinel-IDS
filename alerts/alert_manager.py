"""Alert validation and deduplication."""

import time
from collections import OrderedDict


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


VALID_FIELDS = {
    "rule",
    "severity",
    "description",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "confidence",
}


class AlertManager:

    def __init__(self, on_alert):

        self.on_alert = on_alert

        self._recent = OrderedDict()

        self.counts = {}

    def process(self, alert):

        alert = self._validate(alert)

        # Deduplicate the same detection across changing destination ports.
        # A port scanner should generate ONE alert per source/target/rule,
        # not one alert for every scanned port.
        key = (
            alert["rule"],
            alert.get("src_ip"),
            alert.get("dst_ip"),
        )

        now = time.time()

        # Prevent duplicate alerts for 30 seconds.
        if (
            key in self._recent
            and
            now - self._recent[key] < 30
        ):
            return None

        self._recent[key] = now

        if len(self._recent) > 2000:

            self._recent.popitem(
                last=False
            )

        rule = alert["rule"]

        self.counts[rule] = (
            self.counts.get(rule, 0)
            + 1
        )

        self.on_alert(alert)

        return alert

    def _validate(self, alert):

        if alert["severity"] not in SEVERITY_ORDER:

            raise ValueError(
                f"Invalid severity: "
                f"{alert['severity']}"
            )

        confidence = float(
            alert["confidence"]
        )

        if not 0.0 <= confidence <= 1.0:

            raise ValueError(
                "Confidence must be between 0 and 1"
            )

        return {
            key: value
            for key, value in alert.items()
            if key in VALID_FIELDS
        }
