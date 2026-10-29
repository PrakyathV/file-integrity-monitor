
import argparse
import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

BASELINE_FILE = Path(".fim_baseline.json")
EVENT_LOG = Path("fim_events.log")
CHUNK_SIZE = 4096


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def calculate_hash(file_path):
    """Calculate a SHA-256 hash using chunked reading."""
    digest = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(CHUNK_SIZE), b""):
            digest.update(chunk)

    return digest.hexdigest()


def normalize_directories(directories):
    """Resolve and validate the user-selected directories."""
    resolved = list(dict.fromkeys(Path(item).resolve() for item in directories))

    if not resolved:
        raise ValueError("Select at least one directory.")

    for directory in resolved:
        if not directory.is_dir():
            raise ValueError(f"Not a directory: {directory}")

    return resolved


def scan_directories(directories):
    """Return hashes keyed by absolute file path."""
    results = {}

    for directory in directories:
        for path in directory.rglob("*"):
            if not path.is_file():
                continue

            resolved = path.resolve()

            if resolved in {BASELINE_FILE.resolve(), EVENT_LOG.resolve()}:
                continue

            try:
                results[str(resolved)] = calculate_hash(resolved)
            except OSError as error:
                 raise OSError(f"Scan incomplete: cannot read {resolved}: {error}") from error

    return results


def load_baseline_data():
    """Load and validate the baseline document."""
    if not BASELINE_FILE.exists():
        raise FileNotFoundError(
            "No baseline found. Run with --baseline first."
        )

    data = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))

    if data.get("algorithm") != "SHA-256":
        raise ValueError("Unsupported baseline algorithm.")

    if not isinstance(data.get("files"), dict):
        raise ValueError("Invalid baseline format.")

    if not isinstance(data.get("directories"), list):
        raise ValueError("Baseline has no valid directory list.")

    return data


def load_baseline():
    return load_baseline_data()["files"]


def save_baseline(directories):
    """Create a baseline for all selected directories."""
    files = scan_directories(directories)

    data = {
        "algorithm": "SHA-256",
        "created_at": timestamp(),
        "directories": [str(item) for item in directories],
        "files": files,
    }

    BASELINE_FILE.write_text(
        json.dumps(data, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"[INFO] Baseline saved to {BASELINE_FILE}")
    print(f"[INFO] Recorded {len(files)} files across {len(directories)} directories.")


def log_event(message):
    """Print and append a timestamped event."""
    event = f"{timestamp()} {message}"
    print(event)

    with EVENT_LOG.open("a", encoding="utf-8") as log:
        log.write(event + "\n")


def report_changes(previous, current, baseline):
    """Report state transitions without repeating unchanged alerts."""
    for name in sorted(set(previous) | set(current)):
        old_hash = previous.get(name)
        new_hash = current.get(name)

        if old_hash == new_hash:
            continue

        trusted_hash = baseline.get(name)

        if name not in previous and name in current:
            status = "[NEW]" if trusted_hash is None else "[RESTORED]"
        elif name in previous and name not in current:
            status = "[DELETED]"
        elif trusted_hash is not None and new_hash == trusted_hash:
            status = "[RESTORED]"
        else:
            status = "[MODIFIED]"

        log_event(f"{status} {name}")


def check_directories(directories, baseline, previous):
    """Perform a scan and report changes since the previous scan."""
    current = scan_directories(directories)
    report_changes(previous, current, baseline)
    return current


class ChangeHandler(FileSystemEventHandler):
    """Wake the monitor when a filesystem event occurs."""

    def __init__(self, changed):
        self.changed = changed

    def on_any_event(self, event):
        if not event.is_directory and event.event_type in {
            "created", "modified", "deleted", "moved"
        }:
            self.changed.set()


def monitor(directories, interval):
    """Monitor filesystem events and perform periodic integrity checks."""
    data = load_baseline_data()
    baseline = data["files"]

    if {str(item) for item in directories} != set(data["directories"]):
        raise ValueError(
            "Selected directories do not match the baseline. "
            "Create a new baseline for these directories."
        )

    previous = scan_directories(directories)
    changed = threading.Event()
    observer = Observer()
    handler = ChangeHandler(changed)

    for directory in directories:
        observer.schedule(handler, str(directory), recursive=True)
        print(f"[INFO] Watching {directory}")

    observer.start()
    print(f"[INFO] Periodic integrity check every {interval} seconds.")
    print("[INFO] Press Ctrl+C to stop.")

    try:
        while True:
            # An event triggers a scan early; timeout ensures periodic scans.
            changed.wait(timeout=interval)
            changed.clear()
            time.sleep(0.2)
            previous = check_directories(directories, baseline, previous)
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped.")
    finally:
        observer.stop()
        observer.join()


def main():
    parser = argparse.ArgumentParser(
        description="Multi-directory SHA-256 File Integrity Monitor."
    )
    parser.add_argument(
        "--dirs",
        nargs="+",
        default=["sample_files"],
        help="Directories to monitor (default: sample_files)",
    )

    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--baseline", action="store_true", help="Create a baseline")
    actions.add_argument("--check", action="store_true", help="Check integrity once")
    actions.add_argument("--monitor", action="store_true", help="Monitor continuously")

    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Periodic check interval in seconds (default: 5)",
    )

    args = parser.parse_args()

    if args.interval < 1:
        parser.error("--interval must be at least 1 second")

    try:
        directories = normalize_directories(args.dirs)

        if args.baseline:
            save_baseline(directories)

        elif args.check:
            data = load_baseline_data()
            if {str(item) for item in directories} != set(data["directories"]):
                raise ValueError("Selected directories do not match the baseline.")

            baseline = data["files"]
            current = scan_directories(directories)

            added = sorted(set(current) - set(baseline))
            deleted = sorted(set(baseline) - set(current))
            modified = sorted(
                name for name in set(current) & set(baseline)
                if current[name] != baseline[name]
            )

            if not (added or deleted or modified):
                print("[OK] No file changes detected.")

            for name in added:
                log_event(f"[NEW] {name}")
            for name in modified:
                log_event(f"[MODIFIED] {name}")
            for name in deleted:
                log_event(f"[DELETED] {name}")

        elif args.monitor:
            monitor(directories, args.interval)

    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(1, f"[ERROR] {error}\n")


if __name__ == "__main__":
    main()

