
# Mini Apache Log Analyzer

A lightweight Python-based tool for parsing, analyzing, and detecting potentially suspicious patterns in Apache HTTP Server access logs.

The project focuses on HTTP traffic analysis, basic security monitoring, and automated report generation.

## Features

### Log Parsing
- Parses Apache Combined Access Log Format.
- Extracts IP addresses, timestamps, HTTP methods, requested paths, status codes, response sizes, referrers, and user agents.
- Skips malformed log entries.

### Traffic Analysis
- Counts total HTTP requests.
- Identifies unique IP addresses.
- Calculates total and average response sizes.
- Analyzes HTTP status codes and status groups.
- Identifies the most active IP addresses.
- Identifies the most requested endpoints.
- Counts HTTP methods.

### Security Detection
- Detects unusually high request volumes.
- Identifies repeated HTTP 401 and 403 responses.
- Detects requests to potentially sensitive paths.
- Assigns severity levels to findings.

### Reporting
- Displays analysis results in the terminal.
- Exports reports in TXT format.
- Exports structured reports in JSON format.

## Requirements

- Python 3.10 or newer.
- No external dependencies.

The project uses Python's standard library.

## Project Structure

```text
mini-log-analyzer/
│
├── main.py
├── parser.py
├── analyzer.py
├── detector.py
├── report.py
│
├── logs/
│   └── sample.log
│
├── reports/
│
├── tests/
│   ├── test_parser.py
│   ├── test_analyzer.py
│   └── test_detector.py
│
├── README.md
└── LICENSE
```

## Usage

Clone the repository:

```bash
git clone https://github.com/ryoeh/mini-log-analyzer.git
```

Navigate to the project directory:

```bash
cd mini-log-analyzer
```

Run the analyzer:

```bash
python main.py --file logs/sample.log
```

### Command-line Arguments

| Argument | Description |
|---|---|
| `--file` | Apache log file to analyze (required) |
| `--top` | Number of top IPs and endpoints (default: 5) |
| `--json` | Export analysis as JSON |
| `--txt` | Export analysis as TXT |

### Examples

Display the top 10 IP addresses and endpoints:

```bash
python main.py --file logs/sample.log --top 10
```

Generate a JSON report:

```bash
python main.py --file logs/sample.log --json reports/report.json
```

Generate a TXT report:

```bash
python main.py --file logs/sample.log --txt reports/report.txt
```

Generate both reports:

```bash
python main.py --file logs/sample.log --json reports/report.json --txt reports/report.txt
```

## Testing

The project uses Python's built-in `unittest` framework.

Run all tests:

```bash
python -m unittest discover -s tests -v
```

Run individual test modules:

```bash
python -m unittest discover -s tests -p "test_parser.py" -v
python -m unittest discover -s tests -p "test_analyzer.py" -v
python -m unittest discover -s tests -p "test_detector.py" -v
```

## Detection Logic

The analyzer identifies several potentially suspicious indicators:

- High request volume from a single IP address.
- Repeated HTTP authentication-related errors (401 and 403).
- Requests targeting potentially sensitive endpoints.

These detections are heuristic indicators and do not independently confirm malicious activity.

Thresholds can be configured when calling the detection functions programmatically.

## Limitations

- Supports Apache Combined Access Log Format.
- Does not perform real-time log monitoring.
- Does not use threat intelligence feeds.
- Does not automatically block IP addresses.
- Detection results require further investigation.

## Technologies

- Python
- Regular Expressions
- Collections
- Argparse
- JSON
- Unittest

## License

This project is licensed under the **Ryoeh Proprietary License v1.2**.

All rights not expressly granted by the license are reserved. Viewing the source code does not grant permission to reuse, modify, reproduce, or redistribute it.

For the complete license terms, see the [Ryoeh Proprietary License v1.2](https://github.com/Ryoeh/Ryoeh-License/blob/main/versions/RYOEH-PROPRIETARY-LICENSE-v1.2.txt).

For permission requests, please open an [Issue](https://github.com/Ryoeh/Ryoeh-License/issues).