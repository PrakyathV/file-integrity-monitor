
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.fim import (
    calculate_hash,
    report_changes,
    scan_directories,
)


class TestFileIntegrityMonitor(unittest.TestCase):

    def test_calculate_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "sample.txt"
            file_path.write_text("hello", encoding="utf-8")

            expected = hashlib.sha256(b"hello").hexdigest()
            self.assertEqual(calculate_hash(file_path), expected)

    def test_new_file_detection(self):
        previous = {}
        current = {"/lab/new.txt": "abc"}
        baseline = {}

        with patch("src.fim.log_event") as log_event:
            report_changes(previous, current, baseline)

        log_event.assert_called_once_with("[NEW] /lab/new.txt")

    def test_modified_file_detection(self):
        previous = {"/lab/file.txt": "old"}
        current = {"/lab/file.txt": "new"}
        baseline = {"/lab/file.txt": "original"}

        with patch("src.fim.log_event") as log_event:
            report_changes(previous, current, baseline)

        log_event.assert_called_once_with("[MODIFIED] /lab/file.txt")

    def test_deleted_file_detection(self):
        previous = {"/lab/file.txt": "abc"}
        current = {}
        baseline = {"/lab/file.txt": "abc"}

        with patch("src.fim.log_event") as log_event:
            report_changes(previous, current, baseline)

        log_event.assert_called_once_with("[DELETED] /lab/file.txt")

    def test_unreadable_file_fails_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            file_path = directory / "unreadable.txt"
            file_path.write_text("test", encoding="utf-8")

            with patch(
                "src.fim.calculate_hash",
                side_effect=PermissionError("simulated read failure"),
            ):
                with self.assertRaisesRegex(OSError, "Scan incomplete"):
                    scan_directories([directory])

    def test_preexisting_modification_detection(self):
        baseline = {"/lab/file.txt": "original"}
        previous = baseline.copy()
        current = {"/lab/file.txt": "tampered"}

        with patch("src.fim.log_event") as log_event:
            report_changes(previous, current, baseline)

        log_event.assert_called_once_with("[MODIFIED] /lab/file.txt")

    def test_directory_traversal_error_fails_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)

            with patch(
                "src.fim.os.walk",
                side_effect=lambda *args, **kwargs: self._raise_walk_error(),
            ):
                with self.assertRaisesRegex(OSError, "simulated traversal failure"):
                    scan_directories([directory])

    @staticmethod
    def _raise_walk_error():
        raise PermissionError("simulated traversal failure")


if __name__ == "__main__":
    unittest.main()

