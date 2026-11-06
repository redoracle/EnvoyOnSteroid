"""Mutation-style negative tests for security-test log correlation."""

import json
import unittest

from test_support.waf_logs import (
    backend_uri_marker_hits,
    denied_transactions,
    structured_access_records,
)


def rule_line(rule_id, tx_id):
    return (
        'Coraza: Warning. matched [file "test"] [id "' + rule_id +
        '"] [msg "synthetic"] [unique_id "' + tx_id + '"]'
    )


def denial_line(tx_id, *, phase="http_request_body", action="deny"):
    return (
        'wasm log: Transaction interrupted tx_id="' + tx_id +
        '" context_id=3 action="' + action + '" phase="' + phase + '"'
    )


class RuleDecisionParsingTests(unittest.TestCase):
    def test_same_transaction_rule_and_phase_prove_denial(self):
        logs = "\n".join(
            [rule_line("1000002", "transaction-A"), denial_line("transaction-A")]
        )
        self.assertEqual(
            denied_transactions(
                logs, rule_id="1000002", phase="http_request_body"
            ),
            frozenset({"transaction-A"}),
        )

    def test_other_transaction_interruption_does_not_prove_denial(self):
        # This explicitly catches the previous count-based false positive.
        logs = "\n".join(
            [rule_line("1000002", "transaction-A"), denial_line("transaction-B")]
        )
        self.assertFalse(
            denied_transactions(
                logs, rule_id="1000002", phase="http_request_body"
            )
        )

    def test_header_phase_does_not_prove_phase_two(self):
        logs = "\n".join(
            [
                rule_line("1000002", "transaction-A"),
                denial_line("transaction-A", phase="http_request_headers"),
            ]
        )
        self.assertFalse(
            denied_transactions(
                logs, rule_id="1000002", phase="http_request_body"
            )
        )

    def test_different_rule_id_does_not_prove_expected_rule(self):
        logs = "\n".join(
            [rule_line("920420", "transaction-A"), denial_line("transaction-A")]
        )
        self.assertFalse(
            denied_transactions(
                logs, rule_id="1000002", phase="http_request_body"
            )
        )

    def test_non_denial_action_does_not_prove_block(self):
        logs = "\n".join(
            [
                rule_line("1000002", "transaction-A"),
                denial_line("transaction-A", action="allow"),
            ]
        )
        self.assertFalse(
            denied_transactions(
                logs, rule_id="1000002", phase="http_request_body"
            )
        )

    def test_multiple_transactions_only_return_correct_denials(self):
        logs = "\n".join(
            [
                rule_line("1000002", "wrong-rule-phase"),
                denial_line("wrong-rule-phase", phase="http_request_headers"),
                rule_line("1000002", "correct"),
                rule_line("1000003", "other-rule"),
                denial_line("other-rule"),
                denial_line("correct"),
            ]
        )
        self.assertEqual(
            denied_transactions(
                logs, rule_id="1000002", phase="http_request_body"
            ),
            frozenset({"correct"}),
        )

    def test_blank_and_malformed_logs_fail_closed(self):
        self.assertFalse(
            denied_transactions("", rule_id="1000002", phase="http_request_body")
        )
        self.assertFalse(
            denied_transactions(
                "Coraza: something denied in body",
                rule_id="1000002",
                phase="http_request_body",
            )
        )


class BackendObservationTests(unittest.TestCase):
    def test_only_real_backend_access_messages_count_as_requests(self):
        logs = (
            'backend-1 | time=t level=INFO '
            'msg="200 GET /get?qa_blocked_form=1 0.2ms" status=200\n'
            'envoy-1 | [uri "/post?qa_blocked_form=1"]\n'
            'backend-1 | time=t level=INFO '
            'msg="200 GET /get?qa_barrier_form=1 0.2ms" status=200'
        )
        self.assertEqual(backend_uri_marker_hits(logs, "qa_blocked_form"), 1)
        self.assertEqual(backend_uri_marker_hits(logs, "qa_barrier_form"), 1)
        self.assertEqual(backend_uri_marker_hits(logs, "qa_missing"), 0)

    def test_invalid_marker_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "synthetic token"):
            backend_uri_marker_hits("", "../../etc/passwd")


class AccessLogParsingTests(unittest.TestCase):
    def test_expected_structured_access_event_is_parsed_from_compose_log(self):
        fields = {
            "timestamp": "2026-11-06T00:00:00.000Z",
            "method": "HEAD",
            "response_code": 200,
            "response_code_details": "via_upstream",
            "duration_ms": 2,
            "upstream_cluster": "backend",
            "response_flags": "-",
        }
        raw = "envoy-1  | " + json.dumps(fields, separators=(",", ":"))
        self.assertEqual(structured_access_records(raw), [fields])

    def test_unrelated_or_incomplete_json_is_not_mistaken_for_access_log(self):
        logs = (
            'envoy-1 | {"response_code":403,"method":"GET"}\n'
            'envoy-1 | wasm diagnostic: request URI with \"response_code\"\n'
            'envoy-1 | malformed {"\n'
        )
        self.assertEqual(structured_access_records(logs), [])


if __name__ == "__main__":
    unittest.main()
