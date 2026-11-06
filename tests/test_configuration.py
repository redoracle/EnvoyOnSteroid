"""Static invariants for the supported Envoy/Coraza architecture."""

import json
import pathlib
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.envoy = yaml.safe_load((ROOT / "envoy.yaml").read_text())
        cls.compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
        cls.dockerfile = (ROOT / "Dockerfile").read_text()
        cls.http_config = cls.envoy["static_resources"]["listeners"][0][
            "filter_chains"
        ][0]["filters"][0]["typed_config"]

    def test_yaml_documents_are_mappings(self):
        self.assertIsInstance(self.envoy, dict)
        self.assertIsInstance(self.compose, dict)

    def test_only_v3_http_connection_manager(self):
        self.assertEqual(
            self.http_config["@type"],
            "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
        )

    def test_waf_precedes_router_and_uses_local_artifact(self):
        filters = self.http_config["http_filters"]
        self.assertEqual(
            [item["name"] for item in filters],
            ["envoy.filters.http.wasm", "envoy.filters.http.router"],
        )
        wasm = filters[0]["typed_config"]
        self.assertEqual(
            wasm["@type"],
            "type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm",
        )
        self.assertEqual(
            wasm["config"]["vm_config"]["code"]["local"]["filename"],
            "/etc/envoy/coraza.wasm",
        )
        config = json.loads(wasm["config"]["configuration"]["value"])
        self.assertIn(config["default_directives"], config["directives_map"])
        rules = config["directives_map"]["default"]
        self.assertIn("SecRuleEngine On", rules)
        self.assertIn("Include @crs-setup-conf", rules)
        self.assertIn("Include @owasp_crs/*.conf", rules)
        self.assertTrue(any("/__waf_test_block" in line for line in rules))

    def test_route_cluster_and_compose_backend_match(self):
        cluster = self.envoy["static_resources"]["clusters"][0]
        name = cluster["name"]
        route = self.http_config["route_config"]["virtual_hosts"][0][
            "routes"
        ][0]["route"]
        self.assertEqual(route["cluster"], name)
        self.assertEqual(cluster["load_assignment"]["cluster_name"], name)
        self.assertIn(name, self.compose["services"])
        self.assertEqual(
            cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0][
                "endpoint"
            ]["address"]["socket_address"]["address"],
            name,
        )

    def test_admin_is_loopback_only(self):
        self.assertEqual(
            self.envoy["admin"]["address"]["socket_address"]["address"],
            "127.0.0.1",
        )
        self.assertEqual(
            self.compose["services"]["envoy"]["ports"],
            ["${ENVOY_BIND_ADDRESS:-127.0.0.1}:8080:8080"],
        )

    def test_runtime_is_nonroot_readonly_and_unprivileged(self):
        proxy = self.compose["services"]["envoy"]
        self.assertEqual(proxy["user"], "101:101")
        self.assertTrue(proxy["read_only"])
        self.assertEqual(proxy["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", proxy["security_opt"])
        self.assertIn("USER 101:101", self.dockerfile)
        self.assertIn("ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0", self.dockerfile)
        self.assertIn("envoyproxy/envoy:v1.40.2", self.dockerfile)
        self.assertNotIn("apt-get", self.dockerfile)
        self.assertEqual(
            self.compose["services"]["backend"]["image"],
            "mccutchen/go-httpbin:2.26.0",
        )

    def test_every_runtime_image_has_an_explicit_version(self):
        self.assertNotIn(":latest", self.dockerfile)
        self.assertNotIn(":latest", (ROOT / "docker-compose.yml").read_text())
        self.assertNotIn("docker login", (ROOT / ".github/workflows/ci.yml").read_text())


    def test_untrusted_forwarded_ip_and_ambiguous_paths_rejected(self):
        self.assertTrue(self.http_config["use_remote_address"])
        self.assertEqual(self.http_config["xff_num_trusted_hops"], 0)
        self.assertTrue(self.http_config["normalize_path"])
        self.assertTrue(self.http_config["merge_slashes"])
        self.assertEqual(
            self.http_config["path_with_escaped_slashes_action"], "REJECT_REQUEST"
        )

    def test_untrusted_identity_headers_are_removed_before_upstream(self):
        route = self.http_config["route_config"]["virtual_hosts"][0][
            "routes"
        ][0]
        stripped = set(route["request_headers_to_remove"])
        self.assertTrue(
            {
                "x-forwarded-for",
                "forwarded",
                "x-real-ip",
                "cf-connecting-ip",
                "fly-client-ip",
                "fastly-client-ip",
                "true-client-ip",
                "x-forwarded-host",
                "x-forwarded-proto",
                "x-forwarded-protocol",
                "x-forwarded-ssl",
            }.issubset(stripped)
        )

    def test_structured_access_logs_avoid_request_pii(self):
        logs = self.http_config["access_log"]
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["name"], "envoy.access_loggers.stdout")
        cfg = logs[0]["typed_config"]
        self.assertEqual(
            cfg["@type"],
            "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog",
        )
        fields = cfg["log_format"]["json_format"]
        self.assertIn("response_code", fields)
        self.assertIn("duration_ms", fields)
        self.assertIn("response_flags", fields)
        self.assertNotIn("%REQ(:PATH)%", fields.values())
        self.assertNotIn("%DOWNSTREAM_REMOTE_ADDRESS%", fields.values())
        self.assertNotIn("%REQ(X-FORWARDED-FOR)%", fields.values())

    def test_phase_two_waf_rules_target_parsed_body_fields(self):
        filters = self.http_config["http_filters"]
        wasm = filters[0]["typed_config"]["config"]["configuration"]["value"]
        config = json.loads(wasm)
        directives = config["directives_map"][config["default_directives"]]
        for variable, rule_id in (
            ("ARGS_POST:message", "1000002"),
            ("ARGS:json.message", "1000003"),
        ):
            with self.subTest(variable=variable):
                matched = [d for d in directives if f"SecRule {variable} " in d]
                self.assertEqual(len(matched), 1)
                self.assertIn("phase:2", matched[0])
                self.assertIn(f"id:{rule_id}", matched[0])
                self.assertIn("deny", matched[0])
        self.assertNotIn("SecRule REQUEST_BODY", " ".join(directives))

    def test_backend_and_proxy_limits_and_isolation(self):
        backend = self.compose["services"]["backend"]
        proxy = self.compose["services"]["envoy"]
        for service in (backend, proxy):
            self.assertTrue(service["read_only"])
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertIn("no-new-privileges:true", service["security_opt"])
            self.assertGreater(service["pids_limit"], 0)
            self.assertIn("mem_limit", service)
        self.assertEqual(backend["user"], "10001:10001")
        self.assertNotIn("ports", backend)

    def test_header_limits_and_slow_client_timeouts(self):
        self.assertEqual(self.http_config["max_request_headers_kb"], 32)
        self.assertEqual(self.http_config["request_headers_timeout"], "10s")
        self.assertEqual(self.http_config["stream_idle_timeout"], "60s")
        self.assertEqual(self.http_config["request_timeout"], "30s")

    def test_ci_uses_current_sha_pinned_actions_and_fixed_runner(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            workflow,
        )
        self.assertIn(
            "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
            workflow,
        )
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("ruff check tests", workflow)
        self.assertIn("bash -n tests/smoke.sh", workflow)


if __name__ == "__main__":
    unittest.main()
