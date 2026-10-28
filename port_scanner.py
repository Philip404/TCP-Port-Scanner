#!/usr/bin/env python3
"""Simple TCP port scanner. Only scan hosts you own or have permission to test."""

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(host: str, port: int, timeout: float) -> int | None:
    """Return the port number if it accepts a TCP connection, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return port
    except OSError:
        pass
    return None


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("host", help="Target hostname or IP (e.g. 127.0.0.1)")
    parser.add_argument("-s", "--start", type=int, default=1, help="First port")
    parser.add_argument("-e", "--end", type=int, default=1024, help="Last port")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Seconds per port")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Concurrent threads")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        raise SystemExit(f"Could not resolve host: {args.host}")

    print(f"Scanning {args.host} ({ip}) ports {args.start}-{args.end}...")

    ports = range(args.start, args.end + 1)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = pool.map(lambda p: scan_port(ip, p, args.timeout), ports)
        open_ports = [p for p in results if p is not None]

    if open_ports:
        print("\nOpen ports:")
        for p in open_ports:
            print(f"  {p:<6} {service_name(p)}")
    else:
        print("\nNo open ports found in that range.")


if __name__ == "__main__":
    main()
