from __future__ import annotations

from datetime import datetime
from typing import Dict, Any, List


def _line(title: str, value: str) -> str:
    return f"{title:<22}: {value}"


def build_text_report(data: Dict[str, Any]) -> str:
    # data = result.to_dict() from HeadersAuditResult
    lines: List[str] = []
    lines.append("JordanSec - Defensive Audit Report")
    lines.append("=" * 38)
    lines.append(_line("Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")))
    lines.append(_line("Target", str(data.get("final_url") or data.get("url"))))
    lines.append(_line("HTTPS", "Yes" if data.get("https") else "No"))
    lines.append(_line("Status", str(data.get("status_code"))))
    lines.append(_line("Score", f"{data.get('score', 0)}/100"))
    lines.append("")

    missing = data.get("missing") or []
    warnings = data.get("warnings") or []

    lines.append("Findings")
    lines.append("-" * 38)
    if missing:
        lines.append("Missing Security Headers:")
        for h in missing:
            lines.append(f"  - {h}")
    else:
        lines.append("All common security headers are present.")

    if data.get("cookies"):
        lines.append("")
        lines.append("Cookies")
        lines.append("-" * 38)
        for c in data["cookies"]:
            lines.append(
                f"- {c['name']}: Secure={c['secure']} HttpOnly={c['httponly']} SameSite={c.get('samesite')}"
            )

    if warnings:
        lines.append("")
        lines.append("Recommendations / Notes")
        lines.append("-" * 38)
        for w in warnings:
            lines.append(f"* {w}")

    lines.append("")
    lines.append("Scope & Limitations")
    lines.append("-" * 38)
    lines.append(
        "This is a defensive configuration-level audit. No exploitation or intrusive tests were performed."
    )

    return "\n".join(lines)
