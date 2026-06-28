from __future__ import annotations

import argparse
from pathlib import Path

from edr_engine.ai_analyst.context_loader import SQLiteAnalystContextLoader
from edr_engine.ai_analyst.formatter import format_markdown
from edr_engine.ai_analyst.providers import OllamaAnalystProvider, OpenAIAnalystProvider
from edr_engine.ai_analyst.service import AISecurityAnalyst


def build_provider(name: str):
    if name == "ollama":
        return OllamaAnalystProvider()
    if name == "openai":
        return OpenAIAnalystProvider()
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an AI Security Analyst report from SQLite EDR data.")
    parser.add_argument("--db", type=Path, default=Path("data") / "edr.sqlite", help="SQLite database path.")
    parser.add_argument("--subject", default="Current environment", help="Report subject.")
    parser.add_argument(
        "--provider",
        choices=["deterministic", "ollama", "openai"],
        default="deterministic",
        help="Analyst provider. Ollama/OpenAI fall back to deterministic output if unavailable.",
    )
    args = parser.parse_args()

    context = SQLiteAnalystContextLoader(args.db).load(subject=args.subject)
    analyst = AISecurityAnalyst(provider=build_provider(args.provider))
    report = analyst.generate(context)
    print(format_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
