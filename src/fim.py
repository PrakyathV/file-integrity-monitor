
import argparse
import hashlib
import json
import os
import threading
import time

from datetime import datetime, timezone
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


CONFIG_FILE = Path("fim_config.json").resolve()
BASELINE_DIR = Path(".fim_baselines").resolve()
EVENT_LOG = Path("fim_events.log").resolve()

CHUNK_SIZE = 4096
DEFAULT_INTERVAL = 5


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def calculate_hash(file_path):
    digest = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(CHUNK_SIZE), b""):
            digest.update(chunk)

    return digest.hexdigest()


def normalize_directories(directories):
    resolved = sorted(
        {Path(item).expanduser().resolve() for item in directories},
        key=str,
    )

    if not resolved:
        raise ValueError("Select at least one directory.")

    for directory in resolved:
        if not directory.is_dir():
            raise ValueError(f"Not a valid directory: {directory}")

    for index, directory in enumerate(resolved):
        for other in resolved[index + 1:]:
            if directory in other.parents:
                raise ValueError(
                    f"Overlapping folders are not allowed: "
                    f"{directory} and {other}"
                )

    return resolved


def configuration_id(directories):
    canonical = "\n".join(
        sorted(str(Path(item).resolve()) for item in directories)
    )

    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()[:16]


def baseline_path(directories):
    return BASELINE_DIR / f"{configuration_id(directories)}.json"


def load_config():
    if not CONFIG_FILE.exists():
        return {
            "directories": [],
            "interval": DEFAULT_INTERVAL,
        }

    try:
        data = json.loads(
            CONFIG_FILE.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as error:
        raise ValueError("Configuration contains invalid JSON.") from error

    if not isinstance(data, dict):
        raise ValueError("Invalid configuration format.")

    directories = data.get("directories", [])
    interval = data.get("interval", DEFAULT_INTERVAL)

    if not isinstance(directories, list) or not all(
        isinstance(item, str) for item in directories
    ):
        raise ValueError("Invalid directory configuration.")

    if (
        isinstance(interval, bool)
        or not isinstance(interval, int)
        or interval < 1
    ):
        raise ValueError("Monitoring interval must be positive.")

    return {
        "directories": directories,
        "interval": interval,
    }


def save_config(directories, interval):
    data = {
        "directories": [str(item) for item in directories],
        "interval": interval,
        "updated_at": timestamp(),
    }

    CONFIG_FILE.write_text(
        json.dumps(data, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"[INFO] Configuration saved: {CONFIG_FILE}")


def select_directories():
    config = load_config()
    selected = []

    for item in config["directories"]:
        path = Path(item).expanduser()

        if path.is_dir():
            selected.append(path.resolve())

    while True:
        print("\n========== FIM Folder Selection ==========")
        print("1. Add a folder")
        print("2. Remove a folder")
        print("3. Show selected folders")
        print("4. Save and continue")
        print("5. Exit")

        choice = input("\nChoose an option: ").strip()

        if choice == "1":
            folder = input("Enter folder path: ").strip()

            if not folder:
                print("[ERROR] Folder path cannot be empty.")
                continue

            try:
                selected = normalize_directories(
                    selected + [Path(folder)]
                )
                print("[INFO] Folder added.")
            except (ValueError, OSError) as error:
                print(f"[ERROR] {error}")

        elif choice == "2":
            if not selected:
                print("[INFO] No folders selected.")
                continue

            for index, folder in enumerate(selected, 1):
                print(f"{index}. {folder}")

            try:
                number = int(input("Folder number to remove: "))

                if not 1 <= number <= len(selected):
                    print("[ERROR] Invalid selection.")
                    continue

                removed = selected.pop(number - 1)
                print(f"[INFO] Removed: {removed}")

            except ValueError:
                print("[ERROR] Enter a valid number.")

        elif choice == "3":
            if not selected:
                print("[INFO] No folders selected.")
            else:
                for index, folder in enumerate(selected, 1):
                    print(f"{index}. {folder}")

        elif choice == "4":
            if not selected:
                print("[ERROR] Select at least one folder.")
                continue

            return normalize_directories(selected)

        elif choice == "5":
            raise SystemExit(0)

        else:
            print("[ERROR] Invalid option.")


def scan_directories(directories):
    results = {}

    excluded_directories = {BASELINE_DIR}
    excluded_files = {CONFIG_FILE, EVENT_LOG}

    def raise_walk_error(error):
        raise error

    for directory in normalize_directories(directories):
        for root, dirnames, filenames in os.walk(
            directory,
            topdown=True,
            onerror=raise_walk_error,
            followlinks=False,
        ):
            dirnames[:] = [
                name
                for name in dirnames
                if not (Path(root) / name).is_symlink()
                and (Path(root) / name).resolve()
                not in excluded_directories
            ]

            for filename in filenames:
                path = Path(root) / filename

                try:
                    if path.is_symlink() or not path.is_file():
                        continue

                    resolved = path.resolve()

                    if resolved in excluded_files:
                        continue

                    results[str(resolved)] = calculate_hash(resolved)

                except OSError as error:
                    raise OSError(
                        f"Scan incomplete: cannot inspect or read "
                        f"{path}: {error}"
                    ) from error

    return results


def load_baseline_data(directories):
    path = baseline_path(directories)

    if not path.exists():
        raise FileNotFoundError(
            "No baseline found. Create one before checking or monitoring."
        )

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("Baseline contains invalid JSON.") from error

    if not isinstance(data, dict):
        raise ValueError("Invalid baseline format.")

    if data.get("algorithm") != "SHA-256":
        raise ValueError("Unsupported baseline algorithm.")

    if data.get("directories") != [str(item) for item in directories]:
        raise ValueError("Baseline directory selection does not match.")

    files = data.get("files")

    if not isinstance(files, dict):
        raise ValueError("Invalid baseline file list.")

    if not all(
        isinstance(name, str)
        and isinstance(digest, str)
        and len(digest) == 64
        and all(char in "0123456789abcdef" for char in digest)
        for name, digest in files.items()
    ):
        raise ValueError("Baseline contains invalid file hashes.")

    return data


def save_baseline(directories):
    directories = normalize_directories(directories)
    files = scan_directories(directories)

    BASELINE_DIR.mkdir(parents=True, exist_ok=True)

    data = {
        "algorithm": "SHA-256",
        "created_at": timestamp(),
        "directories": [str(item) for item in directories],
        "files": files,
    }

    path = baseline_path(directories)
    path.write_text(
        json.dumps(data, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"[INFO] Baseline saved: {path}")
    print(f"[INFO] Recorded {len(files)} files.")


def log_event(message):
    event = f"{timestamp()} {message}"
    print(event)

    with EVENT_LOG.open("a", encoding="utf-8") as log:
        log.write(event + "\n")


def report_changes(previous, current, baseline):
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
    current = scan_directories(directories)
    report_changes(previous, current, baseline)
    return current


class ChangeHandler(FileSystemEventHandler):

    def __init__(self, changed):
        self.changed = changed

    def on_any_event(self, event):
        if event.event_type in {
            "created",
            "modified",
            "deleted",
            "moved",
        }:
            self.changed.set()


def monitor(directories, interval):
    data = load_baseline_data(directories)
    baseline = data["files"]
    previous = baseline.copy()

    changed = threading.Event()
    observer = Observer()
    handler = ChangeHandler(changed)

    for directory in directories:
        observer.schedule(handler, str(directory), recursive=True)
        print(f"[INFO] Watching {directory}")

    observer.start()

    print(f"[INFO] Integrity checks every {interval} seconds.")
    print("[INFO] Press Ctrl+C to stop.")

    try:
        previous = check_directories(
            directories, baseline, previous
        )

        while True:
            changed.wait(timeout=interval)
            changed.clear()
            time.sleep(0.2)

            previous = check_directories(
                directories, baseline, previous
            )

    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped.")

    finally:
        observer.stop()
        observer.join()


def main():
    parser = argparse.ArgumentParser(
        description="Interactive multi-folder SHA-256 File Integrity Monitor."
    )

    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--select", action="store_true")
    actions.add_argument("--baseline", action="store_true")
    actions.add_argument("--check", action="store_true")
    actions.add_argument("--monitor", action="store_true")

    parser.add_argument(
        "--interval",
        type=int,
        help="Periodic integrity check interval in seconds.",
    )

    args = parser.parse_args()

    if args.interval is not None and args.interval < 1:
        parser.error("--interval must be at least 1 second")

    try:
        if args.select or not any(
            [args.baseline, args.check, args.monitor]
        ):
            directories = select_directories()
            config = load_config()
            interval = args.interval or config["interval"]
            save_config(directories, interval)

            if not args.baseline and not args.check and not args.monitor:
                print(
                    "[INFO] Folder configuration ready. "
                    "Create a baseline before monitoring."
                )
                return
        else:
            config = load_config()
            directories = normalize_directories(config["directories"])
            interval = args.interval or config["interval"]

        if args.baseline:
            save_baseline(directories)

        elif args.check:
            data = load_baseline_data(directories)
            baseline = data["files"]
            current = scan_directories(directories)

            added = sorted(set(current) - set(baseline))
            deleted = sorted(set(baseline) - set(current))
            modified = sorted(
                name
                for name in set(current) & set(baseline)
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
            monitor(directories, interval)

    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(1, f"[ERROR] {error}\n")


if __name__ == "__main__":
    main()

