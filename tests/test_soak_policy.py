"""Deterministic quality gates for the synthetic loopback soak tool."""

import unittest

from scripts.soak_gateway import (
    assess,
    check_local_origin,
    parse_memory_mib,
    percentile,
)


def healthy_report():
    return {
        "failures": 0,
        "p95_latency_ms": 200,
        "target_rps": 6,
        "observed_rps": 6,
        "memory_peak_mib": 190,
        "memory_growth_mib": 12,
        "duration_seconds": 300,
        "memory_samples_mib": [100] * 12,
    }


class SoakMetricsTests(unittest.TestCase):
    def test_memory_units(self):
        self.assertEqual(parse_memory_mib("1GiB / 2GiB"), 1024)
        self.assertEqual(parse_memory_mib("256MiB / 1GiB"), 256)
        self.assertEqual(parse_memory_mib("1024KiB / 1GiB"), 1)

    def test_unexpected_memory_text_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "memory-usage"):
            parse_memory_mib("not-a-memory-reading")

    def test_nearest_rank_latency_quantiles(self):
        self.assertEqual(percentile([10, 40, 20, 30], 95), 40)
        self.assertEqual(percentile([10, 40, 20, 30], 50), 20)

    def test_healthy_report_passes(self):
        self.assertEqual(assess(healthy_report()), [])

    def test_any_failed_request_fails_gate(self):
        report = healthy_report()
        report["failures"] = 1
        self.assertTrue(assess(report))

    def test_extended_growth_is_gated(self):
        report = healthy_report()
        report["memory_growth_mib"] = 250
        self.assertTrue(any("growth" in x for x in assess(report)))

    def test_short_run_never_claims_a_leak(self):
        report = healthy_report()
        report["duration_seconds"] = 30
        report["memory_growth_mib"] = 250
        self.assertEqual(assess(report), [])

    def test_loopback_guard(self):
        self.assertEqual(
            check_local_origin("http://127.0.0.1:8080"),
            ("127.0.0.1", 8080),
        )
        for invalid in (
            "https://localhost", "http://example.com",
            "http://localhost/path",
        ):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                check_local_origin(invalid)


if __name__ == "__main__":
    unittest.main()
