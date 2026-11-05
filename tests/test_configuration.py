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


if __name__ == "__main__":
    unittest.main()
