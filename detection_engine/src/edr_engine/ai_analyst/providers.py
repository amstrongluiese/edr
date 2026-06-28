from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import asdict

from edr_engine.ai_analyst.models import AnalystInput, AnalystReport


SYSTEM_PROMPT = """You are an AI Security Analyst for an EDR dashboard.
Return strict JSON with these keys:
executive_summary, technical_findings, recommendations, incident_narrative.
Recommendations must be a JSON array of concise analyst actions.
Base the report only on the supplied alerts, incidents, MITRE mappings, and risk scores."""


class AnalystLLMProvider(ABC):
    @abstractmethod
    def generate(self, context: AnalystInput) -> AnalystReport:
        ...


def context_to_prompt(context: AnalystInput) -> str:
    return json.dumps(asdict(context), default=str, sort_keys=True)


def report_from_json(text: str, provider: str) -> AnalystReport:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("LLM response was not valid JSON") from exc

    recommendations = payload.get("recommendations", [])
    if not isinstance(recommendations, list):
        recommendations = [str(recommendations)]

    return AnalystReport(
        executive_summary=str(payload.get("executive_summary", "")).strip(),
        technical_findings=str(payload.get("technical_findings", "")).strip(),
        recommendations=[str(item).strip() for item in recommendations if str(item).strip()],
        incident_narrative=str(payload.get("incident_narrative", "")).strip(),
        metadata={"provider": provider},
    )


class OllamaAnalystProvider(AnalystLLMProvider):
    def __init__(self, model: str | None = None, base_url: str | None = None, timeout: int = 60) -> None:
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.1")
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.timeout = timeout

    def generate(self, context: AnalystInput) -> AnalystReport:
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": context_to_prompt(context)},
            ],
        }
        request = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

        content = data.get("message", {}).get("content", "")
        return report_from_json(content, f"ollama:{self.model}")


class OpenAIAnalystProvider(AnalystLLMProvider):
    def __init__(self, model: str | None = None, api_key: str | None = None, base_url: str | None = None, timeout: int = 60) -> None:
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.base_url = (base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.timeout = timeout

    def generate(self, context: AnalystInput) -> AnalystReport:
        if not self.api_key:
            raise RuntimeError("OPENAI_API_KEY is not configured")
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": context_to_prompt(context)},
            ],
            "response_format": {"type": "json_object"},
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"OpenAI request failed: {exc}") from exc

        content = data["choices"][0]["message"]["content"]
        return report_from_json(content, f"openai:{self.model}")
