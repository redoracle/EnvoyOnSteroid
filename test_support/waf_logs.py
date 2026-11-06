"""Pure, deterministic parsers for test-only Envoy/Coraza log evidence.

WAF decisions must be associated with the *same* Coraza transaction ID.
Counting unrelated rule matches and interruption phases is not sufficient.
Do not emit raw log content in assertion failures: it may contain PII.
"""

import json
import re

_RULE_RE = re.compile(r'\[id "(?P<rule_id>\d+)"\].*\[unique_id "(?P<tx_id>[^"]+)"\]')
_INTERRUPT_RE = re.compile(
    r'Transaction interrupted tx_id="(?P<tx_id>[^"]+)"'
    r'.*\baction="deny"\s+phase="(?P<phase>[^"]+)"'
)
_FIELDS = frozenset(
    {
        "timestamp",
        "method",
        "response_code",
        "response_code_details",
        "duration_ms",
        "upstream_cluster",
        "response_flags",
    }
)


def denied_transactions(raw_logs: str, *, rule_id: str, phase: str) -> frozenset[str]:
    """Return IDs for transactions with matching rule AND denial phase.

    A CRS detection may score an attack and a later CRS anomaly rule can deny
    the same transaction. Both pieces of evidence must share its unique ID.
    """
    matched = set()
    interrupted = set()
    for line in raw_logs.splitlines():
        rule = _RULE_RE.search(line)
        if rule and rule.group("rule_id") == str(rule_id):
            matched.add(rule.group("tx_id"))
        denial = _INTERRUPT_RE.search(line)
        if denial and denial.group("phase") == phase:
            interrupted.add(denial.group("tx_id"))
    return frozenset(matched.intersection(interrupted))


def structured_access_records(raw_logs: str) -> list[dict]:
    """Find Envoy JSON access records without assuming Compose prefix shape."""
    records = []
    for line in raw_logs.splitlines():
        start = line.find('{"')
        if start < 0:
            continue
        try:
            record = json.loads(line[start:])
        except ValueError:
            continue
        if isinstance(record, dict) and _FIELDS.issubset(record):
            records.append(record)
    return records


# go-httpbin writes a structured-ish request outcome in the `msg` field.
# Count URIs only in those backend access messages, not the Coraza logs.
_BACKEND_REQUEST_RE = re.compile(
    r'msg="(?P<status>[1-5][0-9]{2}) (?P<method>[A-Z]+) (?P<uri>/[^" ]*)"'
)


def backend_uri_marker_hits(raw_logs: str, marker: str) -> int:
    """Count actual backend requests carrying a test-only URI marker."""
    if not re.fullmatch(r"[a-z0-9_]+", marker):
        raise ValueError("backend marker must be a simple synthetic token")
    return sum(
        marker in match.group("uri")
        for line in raw_logs.splitlines()
        if (match := _BACKEND_REQUEST_RE.search(line))
    )
