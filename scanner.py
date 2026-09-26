import argparse
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path


COMMON_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
}


def identify_service(port):
    try:
        return socket.getservbyport(port, "tcp")

    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


def scan_port(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            if sock.connect_ex((target, port)) == 0:
                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": identify_service(port),
                }

    except socket.gaierror:
        return None

    except OSError:
        return None

    return None


def parse_port_range(port_range):
    try:
        start, end = map(int, port_range.split("-"))

    except ValueError:
        raise ValueError(
            "Port range must use START-END format, for example: 1-1024"
        )

    if not 1 <= start <= end <= 65535:
        raise ValueError(
            "Port numbers must be between 1 and 65535."
        )

    return range(start, end + 1)


def save_report(target, port_range, workers, open_ports, output_file):
    report = {
        "target": target,
        "scan_type": "tcp_connect_scan",
        "port_range": port_range,
        "worker_count": workers,
        "completed_at": datetime.now().isoformat(timespec="seconds"),
        "open_port_count": len(open_ports),
        "open_ports": open_ports,
    }

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2)

    return output_path


def main():
    parser = argparse.ArgumentParser(
        description="Authorized TCP port scanner"
    )

    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Port range in START-END format. Default: 1-1024"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.8,
        help="Connection timeout in seconds. Default: 0.8"
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=25,
        help="Concurrent worker count. Default: 25"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="results/scan.json",
        help="JSON report output path. Default: results/scan.json"
    )

    args = parser.parse_args()

    try:
        ports = parse_port_range(args.ports)

    except ValueError as error:
        parser.error(str(error))

    if args.workers < 1:
        parser.error("Worker count must be at least 1.")

    print(f"\nScanning authorized target: {args.target}")
    print(f"Port range: {args.ports}")
    print(f"Concurrent workers: {args.workers}\n")

    open_ports = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(
                scan_port,
                args.target,
                port,
                args.timeout,
            )
            for port in ports
        ]

        for future in as_completed(futures):
            result = future.result()

            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda item: item["port"])

    for result in open_ports:
        print(
            f"[OPEN] {result['port']}/tcp "
            f"| Service: {result['service']}"
        )

    report_path = save_report(
        args.target,
        args.ports,
        args.workers,
        open_ports,
        args.output,
    )

    print(f"\nScan complete. Open ports found: {len(open_ports)}")
    print(f"JSON report saved to: {report_path}")


if __name__ == "__main__":
    main()