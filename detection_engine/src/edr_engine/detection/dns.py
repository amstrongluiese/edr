from __future__ import annotations

from typing import Iterable
from uuid import uuid4

from edr_engine.core.events import DetectionFinding, SensorEvent
from edr_engine.core.ports import DetectionProvider


SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "ru", "cn"}


class DnsAnalysisProvider(DetectionProvider):
    @property
    def provider_id(self) -> str:
        return "dns_analysis"

    def evaluate(self, event: SensorEvent) -> Iterable[DetectionFinding]:
        query = self._extract_query(event)
        if query:
            yield from self._evaluate_query(event, query)
            return

        if event.event_type == "network.connection_observed":
            remote_port = int(event.payload.get("remote_port") or 0)
            if remote_port == 53:
                yield self._finding(
                    event,
                    "Direct DNS connection observed",
                    "low",
                    {"category": "dns_transport", "remote_port": remote_port},
                )

    def _evaluate_query(self, event: SensorEvent, query: str) -> Iterable[DetectionFinding]:
        normalized = query.strip(".").lower()
        labels = [label for label in normalized.split(".") if label]
        tld = labels[-1] if labels else ""

        if len(normalized) >= 80 or any(len(label) >= 40 for label in labels):
            yield self._finding(
                event,
                "Unusually long DNS query",
                "medium",
                {"query": normalized, "category": "dns_length_anomaly"},
            )

        if tld in SUSPICIOUS_TLDS:
            yield self._finding(
                event,
                "DNS query uses higher-risk top-level domain",
                "low",
                {"query": normalized, "tld": tld, "category": "dns_tld_reputation"},
            )

        if labels and self._looks_algorithmic(labels[0]):
            yield self._finding(
                event,
                "DNS query has algorithmic-looking label",
                "medium",
                {"query": normalized, "category": "possible_dga"},
            )

    def _extract_query(self, event: SensorEvent) -> str:
        if not event.event_type.startswith("dns."):
            return ""
        for key in ("query", "domain", "hostname", "dns_query"):
            value = event.payload.get(key)
            if value:
                return str(value)
        return ""

    def _looks_algorithmic(self, label: str) -> bool:
        if len(label) < 16:
            return False
        digits = sum(char.isdigit() for char in label)
        hyphens = label.count("-")
        vowels = sum(char in "aeiou" for char in label)
        return digits >= 5 or hyphens >= 3 or vowels <= 2

    def _finding(
        self,
        event: SensorEvent,
        title: str,
        severity: str,
        metadata: dict,
    ) -> DetectionFinding:
        return DetectionFinding(
            finding_id=str(uuid4()),
            event_id=event.event_id,
            provider_id=self.provider_id,
            title=title,
            severity=severity,
            metadata=metadata,
        )
