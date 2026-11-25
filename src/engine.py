import os
import re
from typing import Any, Dict, List
import yaml


def load_rules(rules_dir: str) -> List[Dict[str, Any]]:
    """Loads all Sigma-style YAML rules from the specified directory."""
    if not os.path.isdir(rules_dir):
        raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

    rules: List[Dict[str, Any]] = []
    for filename in sorted(os.listdir(rules_dir)):
        if filename.endswith((".yml", ".yaml")):
            filepath = os.path.join(rules_dir, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
                if rule and "detection" in rule:
                    rule["_source_file"] = filename
                    rules.append(rule)
    return rules


def _match_field(event_val: Any, rule_val: Any, modifier: str = None) -> bool:
    """Evaluates an event field against a rule value (or OR-list) with optional modifiers."""
    if event_val is None:
        return False

    targets = rule_val if isinstance(rule_val, list) else [rule_val]
    ev_str = str(event_val)
    ev_lower = ev_str.lower()

    for target in targets:
        t_str = str(target)
        t_lower = t_str.lower()

        if modifier == "contains" and t_lower in ev_lower:
            return True
        elif modifier == "endswith" and ev_lower.endswith(t_lower):
            return True
        elif modifier == "startswith" and ev_lower.startswith(t_lower):
            return True
        elif modifier == "re" and re.search(t_str, ev_str):
            return True
        elif modifier is None and ev_lower == t_lower:
            return True

    return False


def _match_block(event: Dict[str, Any], block: Dict[str, Any]) -> bool:
    """Returns True only if ALL field conditions inside a detection block match (AND logic)."""
    if not block:
        return False

    for raw_field, expected_val in block.items():
        if "|" in raw_field:
            field_name, modifier = raw_field.split("|", 1)
        else:
            field_name, modifier = raw_field, None

        if not _match_field(event.get(field_name), expected_val, modifier):
            return False

    return True


def evaluate_event(event: Dict[str, Any], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Evaluates a single normalized event against all loaded rules and returns triggered alerts."""
    alerts: List[Dict[str, Any]] = []

    for rule in rules:
        detection = rule.get("detection", {})
        selection = detection.get("selection", {})
        filter_block = detection.get("filter")
        condition = detection.get("condition", "selection").strip().lower()

        is_selected = _match_block(event, selection)
        if not is_selected:
            continue

        # Handle false-positive suppression ('selection and not filter')
        if "not filter" in condition and filter_block:
            if _match_block(event, filter_block):
                continue

        alerts.append({
            "rule_id": rule.get("id", "N/A"),
            "title": rule.get("title", "Untitled Rule"),
            "level": rule.get("level", "medium").upper(),
            "description": rule.get("description", ""),
            "tags": rule.get("tags", []),
            "falsepositives": rule.get("falsepositives", []),
            "event": event,
        })

    return alerts