# Authorized Python Port Scanner

A Python-based TCP port scanner created for cybersecurity learning and authorized security assessments. The tool scans a specified TCP port range, identifies open ports, maps ports to likely services, performs concurrent scanning, and saves results as JSON reports.

> **Ethical-use notice:** Use this project only on systems you own or systems for which you have explicit written authorization. Do not scan public, college, workplace, cloud, or third-party systems without permission.

## Features

- TCP connect scanning with Python's built-in `socket` library
- Configurable target IP address or hostname
- Configurable TCP port range
- Configurable connection timeout
- Concurrent scanning with a limited worker pool
- Likely service identification using port mappings
- JSON report export
- Input validation for port ranges and worker count
- Automated unit tests for port-range validation

## Technologies

- Python 3
- `socket`
- `argparse`
- `concurrent.futures`
- `json`
- `pathlib`
- `unittest`
- Git and GitHub

## Project structure

```text
port-scanner/
├── scanner.py
├── README.md
├── requirements.txt
├── .gitignore
├── sample-report.json
├── results/
└── tests/
    └── test_scanner.py
```

## Installation

Clone the repository:

```bash
git clone [https://github.com/YOUR-GITHUB-USERNAME/port-scanner.git](https://github.com/jahnvi-20m/port-scanner.git)
cd port-scanner
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Activate it on macOS or Linux:

```bash
source .venv/bin/activate
```

## Safe local testing

Start a basic local web server on port `8000`:

```bash
python -m http.server 8000
```

In a separate terminal, scan only your local computer:

```bash
python scanner.py 127.0.0.1 -p 7995-8005
```

Example output:

```text
Scanning authorized target: 127.0.0.1
Port range: 7995-8005
Concurrent workers: 25

[OPEN] 8000/tcp | Service: http-alt

Scan complete. Open ports found: 1
JSON report saved to: results/scan.json
```

Stop the local test server with:

```text
Ctrl + C
```

Run the scan again. The scanner should then report zero open ports in that range.

## Usage

Scan an authorized target and TCP port range:

```bash
python scanner.py 127.0.0.1 -p 1-1024
```

Set a custom timeout:

```bash
python scanner.py 127.0.0.1 -p 7995-8005 --timeout 1.0
```

Set a custom number of concurrent workers:

```bash
python scanner.py 127.0.0.1 -p 7995-8005 --workers 10
```

Save a report with a custom filename:

```bash
python scanner.py 127.0.0.1 -p 7995-8005 -o results/local-test.json
```

Display command help:

```bash
python scanner.py --help
```

## Testing

Run the automated tests:

```bash
python -m unittest discover -s tests
```

Expected output:

```text
.....
----------------------------------------------------------------------
Ran 5 tests in 0.00s

OK
```

## Sample report

See `sample-report.json` for a sanitized JSON report generated from an authorized local test using `127.0.0.1`.

## Limitations

- The tool currently supports IPv4 TCP connect scans only.
- Unsuccessful connection attempts may represent closed, filtered, or unreachable ports.
- Service names are likely mappings based on port numbers, not confirmed software identification.
- Banner grabbing, UDP scanning, IPv6 support, and operating-system detection are not included.
- This project is intended for learning and authorized lab environments.

## Future improvements

- Optional HTTP banner collection
- CSV report export
- IPv6 support
- UDP scanning in an authorized lab
- Optional Scapy-based SYN scan for owned or explicitly authorized systems
- Progress bar and scan-duration measurements
- Streamlit dashboard for report visualization

## Author

MUPPIDI JAHNVI KAPIL