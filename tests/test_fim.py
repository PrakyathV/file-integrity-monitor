
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.fim import (
    calculate_hash,
    normalize_directories,
    configuration_id,
    baseline_path,
    load_config,
    save_config,
    load_baseline_data,
    save_baseline,
    scan_directories,
    report_changes,
)


class TestFileIntegrityMonitor(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.folder = self.root / "documents"
        self.folder.mkdir()

        self.config_patch = patch(
            "src.fim.CONFIG_FILE",
            self.root / "fim_config.json",
        )
        self.baseline_patch = patch(
            "src.fim.BASELINE_DIR",
            self.root / ".fim_baselines",
        )
        self.event_patch = patch(
            "src.fim.EVENT_LOG",
            self.root / "fim_events.log",
        )

        self.config_patch.start()
        self.baseline_patch.start()
        self.event_patch.start()

    def tearDown(self):
        self.config_patch.stop()
        self.baseline_patch.stop()
        self.event_patch.stop()
        self.temp.cleanup()

    def test_calculate_hash(self):
        file_path = self.folder / "sample.txt"
        file_path.write_text("hello", encoding="utf-8")

        expected = hashlib.sha256(b"hello").hexdigest()
        self.assertEqual(calculate_hash(file_path), expected)

    def test_normalize_directories(self):
        result = normalize_directories([self.folder])
        self.assertEqual(result, [self.folder.resolve()])

    def test_duplicate_directories_removed(self):
        result = normalize_directories([self.folder, self.folder])
        self.assertEqual(len(result), 1)

    def test_invalid_directory_rejected(self):
        with self.assertRaises(ValueError):
            normalize_directories([self.root / "missing"])

    def test_empty_directory_selection_rejected(self):
        with self.assertRaises(ValueError):
            normalize_directories([])

    def test_overlapping_directories_rejected(self):
        child = self.folder / "child"
        child.mkdir()

        with self.assertRaises(ValueError):
            normalize_directories([self.folder, child])

    def test_configuration_default(self):
        config = load_config()

        self.assertEqual(config["directories"], [])
        self.assertEqual(config["interval"], 5)

    def test_configuration_save_and_load(self):
        save_config([self.folder], 10)
        config = load_config()

        self.assertEqual(
            config["directories"],
            [str(self.folder.resolve())],
        )
        self.assertEqual(config["interval"], 10)

    def test_invalid_configuration_rejected(self):
        config_path = self.root / "fim_config.json"
        config_path.write_text(
            json.dumps({
                "directories": "invalid",
                "interval": 5,
            }),
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            load_config()

    def test_configuration_id_is_stable(self):
        first = configuration_id([self.folder])
        second = configuration_id([self.folder.resolve()])

        self.assertEqual(first, second)

    def test_baseline_paths_are_selection_specific(self):
        other = self.root / "other"
        other.mkdir()

        self.assertNotEqual(
            baseline_path([self.folder]),
            baseline_path([other]),
        )

    def test_scan_directories(self):
        file_path = self.folder / "sample.txt"
        file_path.write_text("hello", encoding="utf-8")

        result = scan_directories([self.folder])

        self.assertIn(str(file_path.resolve()), result)

    def test_save_and_load_baseline(self):
        file_path = self.folder / "sample.txt"
        file_path.write_text("hello", encoding="utf-8")

        directories = normalize_directories([self.folder])
        save_baseline(directories)

        data = load_baseline_data(directories)

        self.assertEqual(data["algorithm"], "SHA-256")
        self.assertIn(str(file_path.resolve()), data["files"])

    def test_missing_baseline_rejected(self):
        directories = normalize_directories([self.folder])

        with self.assertRaises(FileNotFoundError):
            load_baseline_data(directories)

    def test_new_file_detection(self):
        with patch("src.fim.log_event") as log_event:
            report_changes(
                {},
                {"/lab/new.txt": "abc"},
                {},
            )

        log_event.assert_called_once_with("[NEW] /lab/new.txt")

    def test_modified_file_detection(self):
        with patch("src.fim.log_event") as log_event:
            report_changes(
                {"/lab/file.txt": "old"},
                {"/lab/file.txt": "new"},
                {"/lab/file.txt": "original"},
            )

        log_event.assert_called_once_with("[MODIFIED] /lab/file.txt")

    def test_deleted_file_detection(self):
        with patch("src.fim.log_event") as log_event:
            report_changes(
                {"/lab/file.txt": "abc"},
                {},
                {"/lab/file.txt": "abc"},
            )

        log_event.assert_called_once_with("[DELETED] /lab/file.txt")

    def test_restored_file_detection(self):
        with patch("src.fim.log_event") as log_event:
            report_changes(
                {"/lab/file.txt": "modified"},
                {"/lab/file.txt": "original"},
                {"/lab/file.txt": "original"},
            )

        log_event.assert_called_once_with("[RESTORED] /lab/file.txt")


if __name__ == "__main__":
    unittest.main()

