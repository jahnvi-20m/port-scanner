import argparse
import socket


def scan_port(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((target, port))

            if result == 0:
                return port

    except socket.gaierror:
        print(f"[ERROR] Could not resolve target: {target}")
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

    args = parser.parse_args()

    try:
        ports = parse_port_range(args.ports)

    except ValueError as error:
        parser.error(str(error))

    print(f"\nScanning authorized target: {args.target}")
    print(f"Port range: {args.ports}\n")

    open_ports = []

    for port in ports:
        result = scan_port(args.target, port, args.timeout)

        if result is not None:
            open_ports.append(result)
            print(f"[OPEN] {result}/tcp")

    print(f"\nScan complete. Open ports found: {len(open_ports)}")


if __name__ == "__main__":
    main()