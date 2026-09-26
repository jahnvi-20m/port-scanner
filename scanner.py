import argparse
import socket


def scan_port(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((target, port))

            if result == 0:
                print(f"[OPEN] Port {port}/tcp")
            else:
                print(f"[CLOSED OR FILTERED] Port {port}/tcp")

    except socket.gaierror:
        print(f"[ERROR] Could not resolve target: {target}")

    except OSError as error:
        print(f"[ERROR] Scan failed: {error}")


def main():
    parser = argparse.ArgumentParser(
        description="Authorized TCP port scanner"
    )

    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "port",
        type=int,
        help="TCP port number to scan"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds. Default: 1.0"
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")

    scan_port(args.target, args.port, args.timeout)


if __name__ == "__main__":
    main()