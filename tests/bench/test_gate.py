"""Regression checks for tests/bench/gate.py's handling of repetitions."""

import json
import tempfile
import unittest
from pathlib import Path

import gate


def results_file(entries: list[dict[str, object]]) -> str:
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    with handle:
        json.dump({"benchmarks": entries}, handle)
    return handle.name


def iteration(name: str, cpu_time: float) -> dict[str, object]:
    return {"name": name, "run_type": "iteration", "cpu_time": cpu_time}


class Repetitions(unittest.TestCase):
    def test_given_three_repetitions_when_loaded_then_the_median_is_used(self) -> None:
        # Given: three repetitions whose last one is the outlier.
        path = results_file(
            [
                iteration("gcm/open/aes256/16", 100.0),
                iteration("gcm/open/aes256/16", 102.0),
                iteration("gcm/open/aes256/16", 190.0),
            ]
        )
        # When
        results = gate.load_results(path)
        # Then: the median, not the last repetition
        self.assertEqual(results["gcm/open/aes256/16"], 102.0)
        Path(path).unlink()

    def test_given_aggregate_rows_when_loaded_then_they_are_ignored(self) -> None:
        # Given: Google Benchmark's own mean row beside one measurement.
        path = results_file(
            [
                iteration("ref/open/aes256/16", 90.0),
                {"name": "ref/open/aes256/16_mean", "run_type": "aggregate", "cpu_time": 1.0},
            ]
        )
        # When
        results = gate.load_results(path)
        # Then
        self.assertEqual(results, {"ref/open/aes256/16": 90.0})
        Path(path).unlink()

    def test_given_one_repetition_when_loaded_then_that_measurement_is_used(self) -> None:
        # Given
        path = results_file([iteration("gcm/seal_det/aes128/256", 1234.5)])
        # When
        results = gate.load_results(path)
        # Then
        self.assertEqual(results["gcm/seal_det/aes128/256"], 1234.5)
        Path(path).unlink()


if __name__ == "__main__":
    unittest.main()
