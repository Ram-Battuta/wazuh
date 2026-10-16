"""Triage verdict schema and defensive parsing of model output.

Small models produce malformed JSON more often than large ones. Output is
constrained with a JSON schema where the server supports it, and anything that
still fails validation becomes a ``needs_review`` verdict instead of being dropped:
the sidecar only ever adds context, it never hides a finding.
"""

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

VERDICTS = ("true_positive", "benign", "needs_review")
SEVERITIES = ("critical", "high", "medium", "low", "info")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

MAX_SUMMARY = 600
MAX_ACTIONS = 5
MAX_ACTION_LEN = 200

SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "severity", "confidence", "summary", "mitre_techniques", "recommended_actions"],
    "properties": {
        "verdict": {"type": "string", "enum": list(VERDICTS)},
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "summary": {"type": "string", "maxLength": MAX_SUMMARY},
        "mitre_techniques": {"type": "array", "items": {"type": "string"}, "maxItems": 5},
        "recommended_actions": {"type": "array", "items": {"type": "string"}, "maxItems": MAX_ACTIONS},
    },
}


@dataclass
class Verdict:
    verdict: str = "needs_review"
    severity: str = "medium"
    confidence: float = 0.0
    summary: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    parse_error: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _extract_json(text: str) -> Any:
    """Parse JSON, tolerating code fences or prose around the object."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise
        return json.loads(text[start:end + 1])


def parse_verdict(text: str) -> Verdict:
    """Turn raw model output into a validated Verdict, falling back to needs_review."""
    try:
        data = _extract_json(text)
    except (json.JSONDecodeError, TypeError):
        return Verdict(summary="Model output was not valid JSON.", parse_error=True)
    if not isinstance(data, dict):
        return Verdict(summary="Model output was not a JSON object.", parse_error=True)

    out = Verdict()
    errors = []

    verdict = str(data.get("verdict", "")).strip().lower()
    if verdict in VERDICTS:
        out.verdict = verdict
    else:
        errors.append("verdict")

    severity = str(data.get("severity", "")).strip().lower()
    if severity in SEVERITIES:
        out.severity = severity
    else:
        errors.append("severity")

    try:
        out.confidence = min(1.0, max(0.0, float(data.get("confidence", 0.0))))
    except (TypeError, ValueError):
        errors.append("confidence")

    out.summary = str(data.get("summary", ""))[:MAX_SUMMARY]

    techniques = data.get("mitre_techniques") or []
    if isinstance(techniques, list):
        out.mitre_techniques = [t.strip().upper() for t in techniques
                                if isinstance(t, str) and MITRE_RE.match(t.strip().upper())][:5]

    actions = data.get("recommended_actions") or []
    if isinstance(actions, list):
        out.recommended_actions = [str(a)[:MAX_ACTION_LEN] for a in actions if str(a).strip()][:MAX_ACTIONS]

    if errors:
        # A verdict we could not read must not be trusted, whatever else parsed.
        out.verdict = "needs_review"
        out.parse_error = True
    return out
