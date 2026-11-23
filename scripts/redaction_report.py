"""Report the synthetic corpus results without emitting matched secrets."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from redaction_corpus import NEGATIVE, POSITIVE, UNSUPPORTED

from relayvault.redaction import Detector


def main():
    detector = Detector()
    missed = [
        name
        for name, text, secret in POSITIVE
        if not any(secret in text[f.start : f.end] for f in detector.scan(text))
    ]
    false_positives = [name for name, text in NEGATIVE if detector.scan(text)]
    print(
        json.dumps(
            {
                "synthetic_sensitive_cases": len(POSITIVE),
                "missed_cases": missed,
                "synthetic_benign_cases": len(NEGATIVE),
                "false_positives": false_positives,
                "known_unsupported": [name for name, _ in UNSUPPORTED],
                "limitation": "Curated regression coverage, not a real-world accuracy estimate.",
            },
            indent=2,
        )
    )
    if missed or false_positives:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
