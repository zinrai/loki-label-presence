#!/usr/bin/env python3
"""What the tool does with the values it is given: a failed query never reads as an absent
value, an unindexed label is refused, and an expectation file is read strictly."""

# Not mocked, and not extended to the wiring in run(): every decision the verdict rests on
# is a function over plain values, and what is left over is a sequence of calls that can be
# absent but cannot be wrong. Covered here are the decisions whose failure would be silent.

import json
import unittest

import loki_label_presence as llp


class TestQuery(unittest.TestCase):
    """Queries take the form {label="value"}, with the value quoted and escaped."""

    def test_build(self):
        self.assertEqual(llp.build_query("host", "10.0.0.1"), '{host="10.0.0.1"}')
        self.assertEqual(llp.build_query("host", 'a"b\\c'), '{host="a\\"b\\\\c"}')


class TestExpectations(unittest.TestCase):
    """An expectation file yields description and value pairs in file order. Identical
    entries collapse, a value with two descriptions does not, and unknown keys are
    rejected."""

    def test_pairs_are_kept_in_order_and_deduplicated(self):
        label, entries = llp.parse_expectations(
            {
                "label": "host",
                "values": [
                    {"description": "app-01", "value": "10.0.0.1"},
                    {"description": "app-02", "value": " 10.0.0.2 "},
                    {"description": "app-01", "value": "10.0.0.1"},
                ],
            }
        )
        self.assertEqual(label, "host")
        self.assertEqual(
            entries,
            [
                {"description": "app-01", "value": "10.0.0.1"},
                {"description": "app-02", "value": "10.0.0.2"},
            ],
        )

    def test_one_value_with_two_descriptions_is_rejected(self):
        with self.assertRaises(llp.ProbeError) as cm:
            llp.parse_expectations(
                {
                    "label": "host",
                    "values": [
                        {"description": "app-01", "value": "10.0.0.1"},
                        {"description": "app-02", "value": "10.0.0.1"},
                    ],
                }
            )
        self.assertIn("10.0.0.1", str(cm.exception))

    def test_unknown_key_is_rejected(self):
        with self.assertRaises(llp.ProbeError) as cm:
            llp.parse_expectations(
                {
                    "label": "host",
                    "values": [{"description": "app-01", "value": "10.0.0.1"}],
                    "match": {"job": "app"},
                }
            )
        self.assertIn("match", str(cm.exception))

    def test_shipped_example_matches_the_parser(self):
        with open("expectations.json.example", "rb") as f:
            data = json.loads(f.read().decode("utf-8"))

        label, entries = llp.parse_expectations(data)
        self.assertTrue(label)
        self.assertTrue(entries)


class TestExitCode(unittest.TestCase):
    """A logcli run that exits non-zero raises, and one that exits zero does not."""

    def test_nonzero_exit_raises(self):
        with self.assertRaises(llp.ProbeError) as cm:
            llp.check_exit(1, ["logcli", "query"], "error response from server: 401")
        self.assertIn("401", str(cm.exception))

    def test_zero_exit_passes(self):
        self.assertIsNone(llp.check_exit(0, ["logcli", "query"], ""))


class TestQueryOutput(unittest.TestCase):
    """No output means the value is absent. Output carrying a timestamp means it is
    present at that time. Output without one is refused."""

    def test_no_output_is_absent(self):
        self.assertIsNone(llp.read_query_output(""))

    def test_timestamp_is_returned(self):
        line = json.dumps(
            {"line": "log line", "timestamp": "2026-08-19T09:00:00+09:00"}
        )
        self.assertEqual(
            llp.read_query_output(line + "\n"), "2026-08-19T09:00:00+09:00"
        )

    def test_output_without_timestamp_raises(self):
        line = json.dumps({"line": "log line"})
        with self.assertRaises(llp.ProbeError) as cm:
            llp.read_query_output(line + "\n")
        self.assertIn("timestamp", str(cm.exception))


class TestLabelCheck(unittest.TestCase):
    """A label absent from the range is refused, naming the labels that are present."""

    def test_absent_label_raises(self):
        with self.assertRaises(llp.ProbeError) as cm:
            llp.check_label_present(["job", "host"], "hostt")
        self.assertIn("hostt", str(cm.exception))
        self.assertIn("job", str(cm.exception))

    def test_present_label_passes(self):
        self.assertIsNone(llp.check_label_present(["job", "host"], "host"))


if __name__ == "__main__":
    unittest.main()
