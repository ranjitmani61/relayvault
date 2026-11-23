"""Pattern detection, without storage or logging of matched values.

Coverage is intentionally finite. A clean scan is not a confidentiality proof.
Custom regular expressions are trusted administrator configuration.
"""

import ipaddress
import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

TOKEN_RE = re.compile(r"<RV_VAULT:[A-Z0-9_]+:(?:v2_[0-9a-f]{32}|[0-9a-f]{10})>")
TOKEN_LIKE_RE = re.compile(r"<RV_VAULT:[^\r\n<>]*(?:>|(?=\r|\n|$))")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def shannon_entropy(data: str) -> float:
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in Counter(data).values()) if data else 0.0


def luhn_checksum_valid(value: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", value)]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    return (
        sum(d if i % 2 == 0 else (2 * d - 9 if d > 4 else 2 * d) for i, d in enumerate(reversed(digits))) % 10
        == 0
    )


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int


PATTERNS = [
    ("PRIVATE_KEY_BLOCK", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    ("ANTHROPIC_KEY", r"\bsk-ant-api\d{2}-[A-Za-z0-9_-]{20,}\b"),
    ("OPENAI_KEY", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
    ("GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GITHUB_TOKEN", r"\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
    ("SLACK_TOKEN", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    ("STRIPE_KEY", r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z_]{24,}(?![0-9a-zA-Z_])"),
    ("JWT_TOKEN", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ("AUTH_CREDENTIAL", r"(?i)\b(?:Bearer|Basic)\s+(?P<value>[A-Za-z0-9._~+/=-]+)"),
    (
        "GENERIC_BEARER_ASSIGNMENT",
        r"""(?ix)\b(?:[a-z0-9]+[_-])*(?:api[_-]?key|secret|password|token|passwd|access[_-]?key|client[_-]?secret)\b["']?\s*[:=]\s*(?:"(?P<double>(?:\\.|[^"\r\n])+?)"|'(?P<single>(?:\\.|[^'\r\n])+?)'|(?P<bare>\$\{[^}\r\n]+\}|[^\\\s,;\]}"']+))""",
    ),
    ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("IPV4_PRIVATE_OR_PROD", r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){1,3}\b"),
    ("CREDIT_CARD", r"(?<![\w.])(?:\d[ -]?){12,18}\d(?![\w.])"),
]
PLACEHOLDER_RE = re.compile(r"(?:\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|<[^>]+>|None|null|true|false)\Z")
OPAQUE_RE = re.compile(r"(?<![\w])(?=[A-Za-z0-9_+/=-]{24,}(?![\w]))[A-Za-z0-9_+/=-]+")


class Detector:
    def __init__(self):
        self.patterns = [(name, re.compile(pattern)) for name, pattern in PATTERNS]
        path = os.environ.get("RELAYVAULT_DETECTORS_FILE")
        if path:
            definitions = json.loads(Path(path).read_text())
            for entry in definitions:
                if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,39}", entry["name"]):
                    raise ValueError("Invalid custom detector name")
                pattern = re.compile(entry["pattern"])
                if pattern.match(""):
                    raise ValueError("Custom detectors must not match empty text")
                self.patterns.insert(0, (entry["name"], pattern))

    def scan(self, text: str) -> list[Finding]:
        protected = [m.span() for m in TOKEN_RE.finditer(text)]
        candidates = []
        for priority, (kind, pattern) in enumerate(self.patterns):
            for match in pattern.finditer(text):
                group = next(
                    (
                        name
                        for name in ("value", "double", "single", "bare")
                        if name in match.re.groupindex and match.group(name) is not None
                    ),
                    0,
                )
                start, end = match.span(group)
                value = text[start:end]
                if any(a <= start and end <= b for a, b in protected):
                    continue
                if kind == "IPV4_PRIVATE_OR_PROD":
                    try:
                        addr = ipaddress.IPv4Address(value)
                    except ipaddress.AddressValueError:
                        continue
                    if not any(addr in network for network in PRIVATE_NETWORKS):
                        continue
                if kind == "CREDIT_CARD" and not luhn_checksum_valid(value):
                    continue
                if kind == "GENERIC_BEARER_ASSIGNMENT" and PLACEHOLDER_RE.fullmatch(value):
                    continue
                # Preserve known token spans without exempting neighboring secret text.
                cursor = start
                for a, b in protected:
                    if cursor < b and end > a:
                        if cursor < a and text[cursor:a].strip():
                            candidates.append((cursor, a, priority, kind))
                        cursor = max(cursor, b)
                if cursor < end and text[cursor:end].strip():
                    candidates.append((cursor, end, priority, kind))
        # Prefer enclosing findings (e.g. an entire PEM block) and then detector priority.
        chosen = []
        for start, end, priority, kind in sorted(candidates, key=lambda c: (-(c[1] - c[0]), c[2], c[0])):
            if not any(start < f.end and end > f.start for f in chosen):
                chosen.append(Finding(kind, start, end))
        return sorted(chosen, key=lambda f: f.start)

    def uncertain(self, text: str) -> list[Finding]:
        masked = TOKEN_RE.sub(lambda m: " " * len(m.group()), text)
        findings = []
        for match in OPAQUE_RE.finditer(masked):
            value = match.group()
            # Hex digests are common benign identifiers; they are not automatically secrets.
            if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
                continue
            if (
                any(c.islower() for c in value)
                and any(c.isupper() for c in value)
                and any(c.isdigit() for c in value)
                and shannon_entropy(value) >= 3.8
            ):
                findings.append(Finding("UNCLASSIFIED_CREDENTIAL", *match.span()))
        return findings

    def validate_identifier(self, value: str, field: str) -> None:
        if (
            not isinstance(value, str)
            or not IDENTIFIER_RE.fullmatch(value)
            or self.scan(value)
            or self.uncertain(value)
        ):
            raise ValueError(f"Invalid or sensitive {field}; use a short non-sensitive identifier")


PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
