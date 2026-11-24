"""Detection rules and redaction engine for VaultlessSecrets.

Each rule = a name, a secret type, and a regex describing the SHAPE of the secret.
Includes text redaction and JSON-field-aware structured redaction.
"""
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass(frozen=True)
class Rule:
    name: str          # unique rule id, stored in incident records later
    secret_type: str   # label used in the redaction placeholder
    pattern: re.Pattern
    replacer: Optional[Callable[[re.Match, "Rule"], str]] = None
    extractor: Optional[Callable[[re.Match], str]] = None


def hash_secret(secret_text: str) -> str:
    """Compute deterministic SHA-256 hash of a secret for correlation."""
    return hashlib.sha256(secret_text.encode("utf-8")).hexdigest()


def _default_replacer(match: re.Match, rule: Rule) -> str:
    return f"[REDACTED:{rule.secret_type}]"


def _uri_password_replacer(match: re.Match, rule: Rule) -> str:
    # Retains protocol, user, host, port, db; redacts only :password@
    return f"{match.group(1)}[REDACTED:{rule.secret_type}]{match.group(3)}"


def _uri_password_extractor(match: re.Match) -> str:
    # Extracts only the raw password part from uri match
    return match.group(2)


RULES = [
    # JWT: eyJ<header>.eyJ<payload>.<signature>
    Rule(
        name="jwt_shape_v1",
        secret_type="JWT",
        pattern=re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ),
    # AWS access key ID: AKIA (long-term) or ASIA (temporary) + 16 uppercase letters/digits
    Rule(
        name="aws_access_key_id_v1",
        secret_type="AWS_ACCESS_KEY_ID",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    # Private Key blocks: PKCS#1, PKCS#8, EC, OpenSSH, etc.
    Rule(
        name="private_key_block_v1",
        secret_type="PRIVATE_KEY",
        pattern=re.compile(
            r"-----BEGIN(?: [A-Z0-9_-]+)? PRIVATE KEY-----[A-Za-z0-9+/=\s\r\n]+?-----END(?: [A-Z0-9_-]+)? PRIVATE KEY-----"
        ),
    ),
    # Password in connection URI: e.g. postgres://user:password@host:5432/db
    Rule(
        name="uri_password_v1",
        secret_type="PASSWORD",
        pattern=re.compile(
            r"([a-zA-Z][a-zA-Z0-9+.-]+://[^:\s/@]+:)([^@\s/]+)(@[^\s\"'>]+)"
        ),
        replacer=_uri_password_replacer,
        extractor=_uri_password_extractor,
    ),
]


def redact_text(text: str, location_prefix: str = "raw_log") -> tuple[str, list[dict]]:
    """Replace secrets in a raw string.

    Returns (clean_text, findings). Findings never contain the secret itself.
    """
    findings: list[dict] = []

    for rule in RULES:
        def _replace(match: re.Match, rule: Rule = rule) -> str:
            raw_secret = rule.extractor(match) if rule.extractor else match.group(0)
            secret_hash = hash_secret(raw_secret)
            findings.append({
                "type": rule.secret_type,
                "rule": rule.name,
                "hash": secret_hash,
                "location": location_prefix,
            })
            if rule.replacer:
                return rule.replacer(match, rule)
            return _default_replacer(match, rule)

        text = rule.pattern.sub(_replace, text)

    return text, findings


def redact_json_structure(data: Any, current_path: str = "") -> tuple[Any, list[dict]]:
    """Recursively redact nested JSON fields while tracking the exact dot-notated field path."""
    findings: list[dict] = []

    if isinstance(data, dict):
        new_dict = {}
        for k, v in data.items():
            field_path = f"{current_path}.{k}" if current_path else str(k)
            redacted_val, child_findings = redact_json_structure(v, field_path)
            new_dict[k] = redacted_val
            findings.extend(child_findings)
        return new_dict, findings

    elif isinstance(data, list):
        new_list = []
        for idx, item in enumerate(data):
            field_path = f"{current_path}[{idx}]"
            redacted_val, child_findings = redact_json_structure(item, field_path)
            new_list.append(redacted_val)
            findings.extend(child_findings)
        return new_list, findings

    elif isinstance(data, str):
        path_name = current_path if current_path else "value"
        clean_str, str_findings = redact_text(data, location_prefix=path_name)
        findings.extend(str_findings)
        return clean_str, findings

    else:
        return data, findings


def redact(text: str, default_location: str = "raw_log") -> tuple[str, list[dict]]:
    """Inspect and redact secrets from a log line.

    If the text is valid JSON (object or array), parses and redacts each field recursively,
    accurately recording the field location (e.g. 'request.headers.Authorization')
    while preserving valid JSON syntax without altering formatting/indentation unnecessarily.
    Otherwise, treats it as unstructured plaintext.
    """
    stripped = text.strip()
    if (stripped.startswith("{") and stripped.endswith("}")) or (
        stripped.startswith("[") and stripped.endswith("]")
    ):
        try:
            parsed = json.loads(text)
            clean_struct, findings = redact_json_structure(parsed)
            # Re-serialize to JSON string
            return json.dumps(clean_struct, separators=(",", ":")), findings
        except (json.JSONDecodeError, TypeError):
            pass

    return redact_text(text, location_prefix=default_location)
