"""
Unit tests for src.tracer.schema — the single source of truth for the on-disk
trace format (CSV headers + manifest.json).
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tracer import schema


# Expected column counts INCLUDING the trailing mono_ns column. These must match
# the number of fields each callback passes to format_csv_row.
EXPECTED_COLUMN_COUNTS = {
    "fs": 23,                  # 22 documented + mono_ns
    "block": 17,               # 16 documented (incl. aligned flags col) + mono_ns
    "cache": 11,               # 10 + mono_ns
    "nw_conn": 18,             # 17 + mono_ns
    "nw_sockopt": 10,          # 9 + mono_ns
    "nw_drop": 14,             # 13 + mono_ns
    "process": 12,             # 11 + mono_ns
    "filesystem_snapshot": 7,  # 6 + mono_ns
}

# Cross-OS aligned shared column prefix. These leading columns must match the
# Windows tracer's fs/ds streams exactly and in the same order. (The Linux
# block stream is named ``block``; the Windows equivalent is named ``ds``, but
# the column layouts are identical.)
ALIGNED_FS_PREFIX = [
    "timestamp", "operation", "pid", "tid", "command", "filename",
    "size", "offset", "bytes_completed", "inode", "device", "flags",
]
ALIGNED_DS_PREFIX = [
    "timestamp", "operation", "pid", "tid", "command", "sector",
    "size", "latency_ms", "device", "flags",
]


class SchemaShapeTests(unittest.TestCase):
    def test_schema_version_is_1(self):
        self.assertEqual(schema.SCHEMA_VERSION, 1)

    def test_fs_block_aligned_prefix(self):
        self.assertEqual(schema.column_names("fs")[:len(ALIGNED_FS_PREFIX)],
                         ALIGNED_FS_PREFIX)
        self.assertEqual(schema.column_names("block")[:len(ALIGNED_DS_PREFIX)],
                         ALIGNED_DS_PREFIX)

    def test_all_streams_present(self):
        self.assertEqual(set(schema.STREAMS), set(EXPECTED_COLUMN_COUNTS))

    def test_column_counts(self):
        for key, expected in EXPECTED_COLUMN_COUNTS.items():
            self.assertEqual(len(schema.column_names(key)), expected,
                             f"{key} column count")

    def test_first_column_is_timestamp(self):
        for key in schema.STREAMS:
            self.assertIn("timestamp", schema.column_names(key)[0],
                          f"{key} first column should be a timestamp")

    def test_last_column_is_mono_ns(self):
        for key in schema.STREAMS:
            self.assertEqual(schema.column_names(key)[-1], "mono_ns",
                             f"{key} last column should be mono_ns")

    def test_column_names_unique_per_stream(self):
        for key in schema.STREAMS:
            names = schema.column_names(key)
            self.assertEqual(len(names), len(set(names)), f"{key} has duplicate columns")


class HeaderTests(unittest.TestCase):
    def test_header_line_matches_columns(self):
        for key in schema.STREAMS:
            self.assertEqual(schema.header_line(key).split(","),
                             schema.column_names(key))

    def test_header_has_no_newline(self):
        for key in schema.STREAMS:
            self.assertNotIn("\n", schema.header_line(key))


class ManifestTests(unittest.TestCase):
    def test_manifest_block_is_json_serializable(self):
        block = schema.schema_for_manifest()
        # Round-trips through JSON without error.
        restored = json.loads(json.dumps(block))
        self.assertEqual(restored["schema_version"], 1)
        self.assertEqual(set(restored["streams"]), set(EXPECTED_COLUMN_COUNTS))

    def test_manifest_columns_carry_type_and_unit(self):
        block = schema.schema_for_manifest()
        for key, sdef in block["streams"].items():
            for col in sdef["columns"]:
                self.assertIn("name", col)
                self.assertIn("type", col)
                self.assertIn("unit", col)


if __name__ == "__main__":
    unittest.main()
