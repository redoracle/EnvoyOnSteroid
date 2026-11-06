"""Keep unsupported streaming upgrade routes out of the bounded WAF demo."""

import pathlib
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]


class StreamingSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.envoy = yaml.safe_load((ROOT / "envoy.yaml").read_text())

    def test_single_http_listener_has_no_uninspected_upgrade_path(self):
        listeners = self.envoy["static_resources"]["listeners"]
        self.assertEqual(len(listeners), 1)
        for listener in listeners:
            for chain in listener["filter_chains"]:
                for item in chain["filters"]:
                    hcm = item["typed_config"]
                    self.assertNotIn("upgrade_configs", hcm)
                    self.assertEqual(
                        [f["name"] for f in hcm["http_filters"]],
                        [
                            "envoy.filters.http.buffer",
                            "envoy.filters.http.wasm",
                            "envoy.filters.http.buffer",
                            "envoy.filters.http.router",
                        ],
                    )
                    for host in hcm["route_config"]["virtual_hosts"]:
                        for route in host["routes"]:
                            self.assertNotIn("upgrade_configs", route)
                            self.assertNotIn(
                                "upgrade_configs", route.get("route", {})
                            )
                            self.assertNotIn("connect_matcher", route["match"])

    def test_no_alternate_unprotected_backend(self):
        clusters = self.envoy["static_resources"]["clusters"]
        self.assertEqual([c["name"] for c in clusters], ["backend"])


if __name__ == "__main__":
    unittest.main()
