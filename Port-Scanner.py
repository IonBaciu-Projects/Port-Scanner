import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Tuple

def parse_ports(ports_arg: str) -> List[int]:
    """Parse port argument like '1-1024', '22,80,443', or a combination."""
    ports = set()
    for part in ports_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            start = int(start)
            end = int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def scan_port(host: str, port: int, timeout: float) -> Tuple[int, bool, str]:

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                # Optional: try to grab a simple banner (non-blocking)
                try:
                    sock.settimeout(0.5)
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    banner = ""
                return port, True, banner
            else:
                return port, False, ""
    except Exception as e:
        return port, False, f"error:{e}"

def resolve_host(target: str) -> str:
    return socket.gethostbyname(target)

def main():
    parser = argparse.ArgumentParser(description="Simple TCP port scanner (educational use).")
    parser.add_argument("--host", required=True, help="Host to scan (IP or domain).")
    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Ports to scan. Examples: '22,80,443', '1-1024', or '22,80-90'. Default: 1-1024",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent threads (default: 100). Lower if target/network unstable.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.8,
        help="Connection timeout in seconds (default: 0.8).",
    )
    args = parser.parse_args()

    try:
        ip = resolve_host(args.host)
    except socket.gaierror:
        print(f"Could not resolve host: {args.host}")
        return

    ports = parse_ports(args.ports)
    print(f"Scanning {args.host} ({ip})")
    print(f"Ports: {ports[0]} - {ports[-1]}  |  Threads: {args.threads}  |  Timeout: {args.timeout}s")
    start_time = datetime.now()

    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, ip, p, args.timeout): p for p in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                p, is_open, banner = future.result()
            except Exception as exc:
                print(f"[{port}] scan error: {exc}")
                continue

            if is_open:
                open_ports.append((p, banner))
                banner_text = f" - {banner}" if banner else ""
                print(f"[+] Port {p} is OPEN{banner_text}")

    elapsed = datetime.now() - start_time
    print(f"\nScan finished in {elapsed.total_seconds():.2f} seconds.")
    if open_ports:
        print("Open ports:")
        for p, b in sorted(open_ports):
            print(f" - {p}{(' : ' + b) if b else ''}")
    else:
        print("No open ports found in the scanned range.")


if __name__ == "__main__":
    main()