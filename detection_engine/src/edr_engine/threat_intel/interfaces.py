from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Observable:
    value: str
    kind: str


@dataclass(frozen=True)
class IntelResult:
    observable: Observable
    source: str
    reputation: str
    metadata: dict[str, Any]


class ThreatIntelProvider(ABC):
    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Stable provider identifier."""

    @abstractmethod
    def lookup(self, observable: Observable) -> IntelResult | None:
        """Return enrichment for one observable."""
