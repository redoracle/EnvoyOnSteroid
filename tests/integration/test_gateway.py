"""Real-container HTTP contracts and WAF decisions, run after Compose startup.

Keep this directory without __init__.py so offline unittest discovery does
not make network calls. The integration entrypoint runs it explicitly.
"""

import http.client
import ipaddress
import json
import os
import subprocess
import time
import unittest
from dataclasses import dataclass
from urllib.parse import urlsplit

from test_support.waf_logs import denied_transactions, structured_access_records

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8080")
PARSED = urlsplit(BASE_URL)
if PARSED.scheme != "http" or PARSED.path not in ("", "/"):
    raise RuntimeError("BASE_URL must be an HTTP origin without path")
try:
    LOCAL = ipaddress.ip_address(PARSED.hostname or "").is_loopback
except ValueError:
    LOCAL = PARSED.hostname == "localhost"
if not LOCAL:
    raise RuntimeError("Integration tests refuse non-loopback BASE_URL")

HOST = PARSED.hostname
PORT = PARSED.port or 80


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict
    body: bytes

    def as_json(self):
        content_type = self.headers.get("content-type", "")
        if "application/json" not in content_type:
            raise AssertionError(f"Expected JSON, got {content_type}")
        return json.loads(self.body)


def exchange(path, *, method="GET", body=None, headers=None, timeout=6):
    """Send a real HTTP request preserving raw path encoding."""
    connection = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    request_headers = {"Accept": "application/json"}
    request_headers.update(headers or {})
    try:
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        payload = response.read(1024 * 1024 + 1)
        if len(payload) > 1024 * 1024:
            raise AssertionError("Response exceeded the 1 MiB test budget")
        return Response(
            response.status,
            {name.lower(): value for name, value in response.getheaders()},
            payload,
        )
    finally:
        connection.close()


def compose(*args):
    return subprocess.run(
        ("docker", "compose", *args),
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    ).stdout


def logs():
    return compose("logs", "--no-color", "envoy")


def inspect_service(name):
    """Inspect effective Docker security policy, not just Compose YAML."""
    container_id = compose("ps", "--quiet", name).strip()
    if not container_id:
        raise AssertionError(f"No running container for {name}")
    proc = subprocess.run(
        ("docker", "inspect", "--type", "container", container_id),
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    result = json.loads(proc.stdout)
    if len(result) != 1:
        raise AssertionError(f"Expected one container for {name}")
    return result[0]


def wait_for_backend(timeout=60):
    deadline = time.monotonic() + timeout
    detail = "no response"
    while time.monotonic() < deadline:
        try:
            result = exchange("/get", timeout=3)
            if result.status == 200 and result.as_json()["method"] == "GET":
                return
            detail = f"HTTP {result.status}: {result.body[:120]!r}"
        except (OSError, ValueError, AssertionError) as exc:
            detail = str(exc)
        time.sleep(0.25)
    raise AssertionError(f"Backend failed readiness: {detail}")


class GatewayContractTests(unittest.TestCase):
    def test_get_returns_backend_method_query_and_url(self):
        response = exchange("/get?probe=contract-value")
        self.assertEqual(response.status, 200, response.body[:160])
        document = response.as_json()
        self.assertEqual(document["method"], "GET")
        self.assertEqual(document["args"]["probe"], ["contract-value"])
        self.assertTrue(document["url"].endswith("/get?probe=contract-value"))

    def test_json_post_preserves_payload_and_method(self):
        payload = {"message": "benign", "count": 2}
        response = exchange(
            "/post", method="POST", body=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status, 200, response.body[:160])
        document = response.as_json()
        self.assertEqual(document["method"], "POST")
        self.assertEqual(document["json"], payload)

    def test_form_post_preserves_fields_and_method(self):
        response = exchange(
            "/post", method="POST", body="message=benign&count=2",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(response.status, 200, response.body[:160])
        document = response.as_json()
        self.assertEqual(document["method"], "POST")
        self.assertEqual(document["form"]["message"], ["benign"])
        self.assertEqual(document["form"]["count"], ["2"])

    def test_upstream_http_error_is_propagated(self):
        response = exchange("/status/404")
        self.assertEqual(response.status, 404)


class GatewayRequestHandlingTests(unittest.TestCase):
    def test_escaped_path_separators_are_rejected(self):
        for separator in ("%2f", "%2F", "%5c", "%5C"):
            with self.subTest(separator=separator):
                response = exchange(f"/get{separator}../get")
                self.assertEqual(
                    response.status, 400,
                    f"{separator}: {response.status} {response.body[:120]!r}",
                )

    def test_duplicate_slashes_are_normalized(self):
        response = exchange("//get?probe=slashes")
        self.assertEqual(response.status, 200, response.body[:120])
        self.assertEqual(
            response.as_json()["args"]["probe"], ["slashes"]
        )

    def test_headers_above_configured_limit_are_rejected(self):
        response = exchange(
            "/get", headers={"X-QA-Filler": "x" * 34000},
        )
        self.assertEqual(response.status, 431, response.body[:120])

    def test_small_custom_header_reaches_backend(self):
        response = exchange(
            "/get", headers={"X-QA-Check": "benign-token"},
        )
        self.assertEqual(response.status, 200, response.body[:120])
        self.assertEqual(
            response.as_json()["headers"]["X-Qa-Check"],
            ["benign-token"],
        )

    def test_client_supplied_identity_headers_cannot_spoof_upstream(self):
        # go-httpbin trusts several identity headers by default. This
        # verifies Envoy actually removes untrusted client values before
        # forwarding, not just that Envoy itself ignores untrusted XFF.
        spoofed = {
            "X-Forwarded-For": "203.0.113.17",
            "CF-Connecting-IP": "198.51.100.29",
            "Fly-Client-IP": "192.0.2.41",
            "X-Real-IP": "203.0.113.19",
            "Forwarded": "for=203.0.113.21",
            "X-Forwarded-Proto": "https",
        }
        response = exchange("/get", headers=spoofed)
        self.assertEqual(response.status, 200, response.body[:120])
        body = response.as_json()
        forwarded = {
            key.lower(): values for key, values in body["headers"].items()
        }
        for key, value in spoofed.items():
            with self.subTest(header=key):
                self.assertNotIn(value, forwarded.get(key.lower(), []))
        self.assertNotIn(
            body["origin"],
            {"203.0.113.17", "198.51.100.29", "192.0.2.41", "203.0.113.19"},
        )

    def test_structured_access_logs_exclude_synthetic_request_canaries(self):
        # Only structured JSON access logs are intentionally privacy-scoped.
        # Raw Coraza WASM diagnostics can contain matched values/URIs.
        baseline = len(structured_access_records(logs()))
        # HEAD is unique in this serial suite, so its access record can be
        # identified even if Envoy flushes earlier GET/POST records in a batch.
        response = exchange(
            "/get?qa_secret_canary=synthetic-only",
            method="HEAD",
            headers={"Cookie": "qa_cookie_canary=synthetic-only"},
        )
        self.assertEqual(response.status, 200, response.body[:120])
        # Envoy's stdout access-log sink flushes asynchronously (normally
        # around a 10-second file-flush interval); polling for only five
        # seconds produces a false negative even when logs are correct.
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            new_records = structured_access_records(logs())[baseline:]
            # Check every newly flushed access record for accidental data
            # disclosure, regardless of asynchronous batching.
            for record in new_records:
                encoded = json.dumps(record)
                self.assertNotIn("qa_secret_canary", encoded)
                self.assertNotIn("qa_cookie_canary", encoded)
                self.assertNotIn("synthetic-only", encoded)
            head_records = [
                r for r in new_records if r.get("method") == "HEAD"
            ]
            if head_records:
                self.assertEqual(head_records[-1]["response_code"], 200)
                return
            time.sleep(0.2)
        self.fail("No structured JSON access record emitted for HEAD probe")


class RuntimeIsolationTests(unittest.TestCase):
    def assert_service_is_unprivileged(self, service, expected_user):
        inspected = inspect_service(service)
        host = inspected["HostConfig"]
        self.assertEqual(inspected["Config"]["User"], expected_user)
        self.assertTrue(host["ReadonlyRootfs"])
        self.assertFalse(host["Privileged"])
        self.assertIn("ALL", [cap.upper() for cap in host["CapDrop"]])
        self.assertTrue(
            any(
                option.startswith("no-new-privileges")
                for option in (host.get("SecurityOpt") or [])
            )
        )
        self.assertGreater(host["PidsLimit"], 0)
        self.assertGreaterEqual(host["Memory"], 128 * 1024 * 1024)

    def test_proxy_enforces_container_controls_and_loopback_bind(self):
        self.assert_service_is_unprivileged("envoy", "101:101")
        ports = inspect_service("envoy")["HostConfig"]["PortBindings"]
        self.assertEqual(
            ports["8080/tcp"][0]["HostIp"], "127.0.0.1"
        )

    def test_backend_enforces_controls_without_published_ports(self):
        self.assert_service_is_unprivileged("backend", "10001:10001")
        published = inspect_service("backend")["HostConfig"]["PortBindings"]
        self.assertFalse(published)


class GatewayWAFTests(unittest.TestCase):
    def assert_denied_by_rule(self, path, rule_id, phase, **kwargs):
        previous = denied_transactions(
            logs(), rule_id=rule_id, phase=phase
        )
        response = exchange(path, **kwargs)
        self.assertEqual(
            response.status, 403,
            f"Expected Coraza rule {rule_id} (phase={phase}) to deny; "
            f"received {response.status} {response.body[:160]!r}",
        )
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            observed = denied_transactions(
                logs(), rule_id=rule_id, phase=phase
            )
            # A new transaction must contain BOTH the target rule match
            # and the denial/phase event under the same unique ID.
            # This avoids combining different request logs accidentally.
            if observed.difference(previous):
                return
            time.sleep(0.2)
        self.fail(
            f"HTTP 403 did not prove rule {rule_id}/{phase} caused "
            "a new correlated WAF denial"
        )

    def test_custom_uri_rule_blocks_in_phase_one(self):
        self.assert_denied_by_rule(
            "/__waf_test_block", "1000001", "http_request_headers",
        )

    def test_form_body_rule_blocks_in_phase_two(self):
        self.assert_denied_by_rule(
            "/post", "1000002", "http_request_body",
            method="POST", body="message=__waf_test_payload",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def test_json_body_rule_blocks_in_phase_two(self):
        self.assert_denied_by_rule(
            "/post", "1000003", "http_request_body",
            method="POST",
            body=json.dumps({"message": "__waf_test_payload"}),
            headers={"Content-Type": "application/json"},
        )

    def test_crs_xss_detection_not_just_generic_http_403(self):
        self.assert_denied_by_rule(
            "/get?arg=%3Cscript%3Ealert(0)%3C%2Fscript%3E",
            "941100", "http_request_headers",
        )


class UpstreamFailureAndRecoveryTests(unittest.TestCase):
    def test_backend_outage_returns_503_and_recovery_restores_routing(self):
        # Deliberately destructive, serial-only test. Always restore the stack.
        compose("stop", "--timeout", "5", "backend")
        try:
            response = exchange("/get")
            self.assertEqual(
                response.status, 503,
                f"Expected unavailable-upstream 503, received {response.status}",
            )
        finally:
            compose("start", "backend")
        wait_for_backend(timeout=60)
        response = exchange("/get?probe=recovered")
        self.assertEqual(response.status, 200, response.body[:120])
        self.assertEqual(
            response.as_json()["args"]["probe"], ["recovered"]
        )


if __name__ == "__main__":
    unittest.main()
