"""Reduce a raw finding document to the compact view the model sees.

Small models have small context windows and degrade on noise, so only fields that
matter for triage are kept, and free-text fields are truncated.
"""

from typing import Any, Dict, Optional

# (output key, dotted path in the finding document)
FIELDS = [
    ("timestamp", "@timestamp"),
    ("rule_title", "wazuh.rule.title"),
    ("rule_level", "wazuh.rule.level"),
    ("rule_sigma_id", "wazuh.rule.sigma_id"),
    ("rule_tags", "wazuh.rule.tags"),
    ("rule_mitre", "wazuh.rule.mitre"),
    ("integration", "wazuh.integration.name"),
    ("category", "wazuh.integration.category"),
    ("agent_name", "wazuh.agent.name"),
    ("agent_id", "wazuh.agent.id"),
    ("host_os", "wazuh.agent.host.os.name"),
    ("location", "wazuh.protocol.location"),
    ("event_action", "event.action"),
    ("event_outcome", "event.outcome"),
    ("source_ip", "source.ip"),
    ("source_port", "source.port"),
    ("destination_ip", "destination.ip"),
    ("destination_port", "destination.port"),
    ("user_name", "user.name"),
    ("process_name", "process.name"),
    ("process_command_line", "process.command_line"),
    ("parent_process_name", "process.parent.name"),
    ("file_path", "file.path"),
    ("url", "url.full"),
    ("dns_question", "dns.question.name"),
    ("message", "message"),
    ("original", "event.original"),
]

TRUNCATE_KEYS = {"message", "original", "process_command_line", "url"}


def get_path(doc: Dict[str, Any], path: str) -> Optional[Any]:
    """Look up a dotted path, accepting both nested objects and flattened dotted keys."""
    if path in doc:
        return doc[path]
    node: Any = doc
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def compact_finding(source: Dict[str, Any], max_text: int = 1500) -> Dict[str, Any]:
    """Return the triage-relevant subset of a finding ``_source``."""
    view: Dict[str, Any] = {}
    for key, path in FIELDS:
        value = get_path(source, path)
        if value is None or value == "" or value == []:
            continue
        if key in TRUNCATE_KEYS and isinstance(value, str) and len(value) > max_text:
            value = value[:max_text] + f"...[truncated {len(value) - max_text} chars]"
        view[key] = value
    return view
