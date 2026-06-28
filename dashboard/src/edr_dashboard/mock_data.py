from __future__ import annotations


class MockDashboardService:
    def metrics(self) -> list[dict]:
        return []

    def list_assets(self) -> list[dict]:
        return []

    def list_alerts(self) -> list[dict]:
        return []

    def list_incidents(self) -> list[dict]:
        return []

    def list_reports(self) -> list[dict]:
        return []

    def threat_timeline(self) -> list[dict]:
        return []
