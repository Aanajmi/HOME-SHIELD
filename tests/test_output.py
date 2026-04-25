"""Tests for output utilities (JSON/CSV writing)."""

import csv
import json
import os
import tempfile
import unittest

from homeshield.utils.output import write_json, write_csv, load_json, ensure_directory


class TestWriteJson(unittest.TestCase):
    """Test JSON writing functionality."""

    def test_write_and_read(self):
        """Test writing and reading JSON roundtrip."""
        data = {"key": "value", "number": 42, "list": [1, 2, 3]}

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmppath = f.name

        try:
            write_json(data, tmppath)
            loaded = load_json(tmppath)
            self.assertEqual(loaded, data)
        finally:
            os.unlink(tmppath)

    def test_creates_parent_directory(self):
        """Test that parent directories are created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "sub", "dir", "test.json")
            write_json({"test": True}, path)
            self.assertTrue(os.path.isfile(path))

    def test_json_pretty_printed(self):
        """Test that output is pretty-printed with indentation."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            tmppath = f.name

        try:
            write_json({"a": 1}, tmppath)
            with open(tmppath) as fh:
                content = fh.read()
            self.assertIn("\n", content)
            self.assertIn("  ", content)
        finally:
            os.unlink(tmppath)

    def test_load_nonexistent_file(self):
        """Test loading a file that doesn't exist raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            load_json("/tmp/nonexistent_file_12345.json")

    def test_load_invalid_json(self):
        """Test loading invalid JSON raises JSONDecodeError."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("not valid json {{{}}")
            tmppath = f.name

        try:
            with self.assertRaises(json.JSONDecodeError):
                load_json(tmppath)
        finally:
            os.unlink(tmppath)


class TestWriteCsv(unittest.TestCase):
    """Test CSV writing functionality."""

    def test_write_and_read(self):
        """Test writing and reading CSV roundtrip."""
        rows = [
            {"protocol": "mDNS", "round": "1", "responder_ip": "192.168.1.1"},
            {"protocol": "SSDP", "round": "1", "responder_ip": "192.168.1.2"},
        ]
        fieldnames = ["protocol", "round", "responder_ip"]

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            tmppath = f.name

        try:
            write_csv(rows, tmppath, fieldnames)
            with open(tmppath, newline="") as fh:
                reader = csv.DictReader(fh)
                loaded = list(reader)
            self.assertEqual(len(loaded), 2)
            self.assertEqual(loaded[0]["protocol"], "mDNS")
            self.assertEqual(loaded[1]["responder_ip"], "192.168.1.2")
        finally:
            os.unlink(tmppath)

    def test_empty_rows(self):
        """Test writing CSV with no rows produces header only."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            tmppath = f.name

        try:
            write_csv([], tmppath, ["a", "b", "c"])
            with open(tmppath) as fh:
                lines = fh.readlines()
            self.assertEqual(len(lines), 1)  # header only
            self.assertIn("a,b,c", lines[0])
        finally:
            os.unlink(tmppath)

    def test_creates_parent_directory(self):
        """Test that parent directories are created for CSV."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "nested", "test.csv")
            write_csv([{"x": "1"}], path, ["x"])
            self.assertTrue(os.path.isfile(path))


class TestEnsureDirectory(unittest.TestCase):
    """Test directory creation utility."""

    def test_creates_new_directory(self):
        """Test creating a new directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = os.path.join(tmpdir, "new_subdir")
            result = ensure_directory(new_dir)
            self.assertTrue(os.path.isdir(result))

    def test_existing_directory(self):
        """Test that existing directory doesn't cause error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = ensure_directory(tmpdir)
            self.assertTrue(os.path.isdir(result))

    def test_nested_directories(self):
        """Test creating nested directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = os.path.join(tmpdir, "a", "b", "c")
            result = ensure_directory(nested)
            self.assertTrue(os.path.isdir(result))


if __name__ == "__main__":
    unittest.main()
