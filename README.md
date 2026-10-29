
# File Integrity Monitor (FIM)

A Python-based File Integrity Monitor that uses SHA-256 hashing to detect unauthorized or unexpected file changes. It supports multiple directories, baseline comparisons, filesystem event monitoring, and periodic integrity checks.

## Features

- **SHA-256 hashing:** Detects changes in file contents.
- **Multi-directory monitoring:** Monitor multiple selected directories.
- **Baseline creation:** Store a trusted snapshot of file hashes.
- **Integrity checks:** Identify new, modified, and deleted files.
- **Live monitoring:** React to filesystem events using Watchdog.
- **Periodic verification:** Recheck files even when no filesystem event triggers a scan.
- **Timestamped event logs:** Record detected changes in a local log file.
- **Error handling:** Report file-reading and directory-traversal failures instead of treating incomplete scans as clean.
- **Unit tests:** Test hashing, change detection, and scan-error handling.

## Requirements

- Python 3.10 or newer
- Watchdog

## Installation

Clone the repository:

```bash
git clone https://github.com/PrakyathV/file-integrity-monitor.git
cd file-integrity-monitor
```

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install the dependency:

```bash
python -m pip install watchdog
```

## Usage

Run commands from the repository root with the virtual environment activated.

### 1. Create a baseline

Record the current hashes of files in the selected directories:

```bash
python src/fim.py --dirs sample_files tests --baseline
```

### 2. Check integrity once

Compare the current files against the saved baseline:

```bash
python src/fim.py --dirs sample_files tests --check
```

The monitor reports new, modified, and deleted files.

### 3. Start continuous monitoring

Watch for filesystem events and perform periodic integrity checks:

```bash
python src/fim.py --dirs sample_files tests --monitor --interval 5
```

Press `Ctrl+C` to stop monitoring.

### 4. Display command-line options

```bash
python src/fim.py --help
```

## Running the Tests

Run the unit test suite:

```bash
python -m unittest discover -s tests -v
```

The test suite covers SHA-256 hashing, new-file detection, modification detection, deletion detection, pre-existing modification reporting logic, unreadable-file handling, and directory-traversal error handling.

## Project Structure

```text
file-integrity-monitor/
├── src/
│   └── fim.py
├── tests/
│   └── test_fim.py
├── sample_files/
│   └── notes.txt
├── .gitignore
└── README.md
```

The baseline file (`.fim_baseline.json`) and event log (`fim_events.log`) are generated locally and excluded from Git.

## Security Considerations and Limitations

- Protect the baseline file. An attacker who can modify both monitored files and the baseline may undermine integrity checks.
- SHA-256 detects content differences; it does not identify who changed a file or prove that a change was malicious.
- Filesystem events can be missed or coalesced, so periodic integrity checks provide an additional layer of detection.
- Monitoring can require additional permissions for protected files and directories.
- This is a learning and defensive-monitoring project, not a replacement for a production endpoint detection or file integrity management system.

## Learning Outcomes

This project demonstrates practical experience with Python, cryptographic hashing, filesystem monitoring, command-line interfaces, error handling, unit testing, and Git-based project development.

