"""Detection rules for VaultlessSecrets.

Each rule = a name, a secret type, and a regex describing the SHAPE of the secret.
To support a new secret type, add one Rule to RULES and add seed lines for it.
"""
import re
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class Rule:
    name: str          # unique rule id, stored in incident records later
    secret_type: str   # label used in the redaction placeholder
    pattern: re.Pattern
    replacer: Optional[Callable[[re.Match, "Rule"], str]] = None


def _default_replacer(match: re.Match, rule: Rule) -> str:
    return f"[REDACTED:{rule.secret_type}]"


def _uri_password_replacer(match: re.Match, rule: Rule) -> str:
    # Retains protocol, user, host, port, db; redacts only :password@
    return f"{match.group(1)}[REDACTED:{rule.secret_type}]{match.group(3)}"


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
    ),
]


def redact(text: str) -> tuple[str, list[dict]]:
    """Replace every secret found in text.

    Returns (clean_text, findings). Findings never contain the secret itself,
    only the type and the rule that caught it.
    """
    findings: list[dict] = []

    for rule in RULES:
        def _replace(match: re.Match, rule: Rule = rule) -> str:
            findings.append({"type": rule.secret_type, "rule": rule.name})
            if rule.replacer:
                return rule.replacer(match, rule)
            return _default_replacer(match, rule)

        text = rule.pattern.sub(_replace, text)

    return text, findings
