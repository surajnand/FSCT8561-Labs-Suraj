
import socket

HOST = "127.0.0.1"
TIMEOUT = 0.2
MAX_PORTS = 1000


def scan_ports(start_port, end_port):
    # Validate port numbers
    if not isinstance(start_port, int) or not isinstance(end_port, int):
        raise ValueError("Port numbers must be integers")

    if start_port < 1 or end_port > 65535:
        raise ValueError("Ports must be between 1 and 65535")

    if start_port > end_port:
        raise ValueError("Starting port cannot exceed ending port")

    if end_port - start_port + 1 > MAX_PORTS:
        raise ValueError("Maximum scan range is 1000 ports")

    results = []

    print(f"\nScanning {HOST} from port {start_port} to {end_port}...\n")

    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(TIMEOUT)

                result = sock.connect_ex((HOST, port))

                if result == 0:
                    status = "OPEN"
                elif result in (10061, 111):
                    status = "CLOSED"
                else:
                    status = "UNKNOWN"

        except socket.timeout:
            status = "TIMEOUT"

        except OSError:
            status = "ERROR"

        results.append({
            "port": port,
            "status": status
        })

        if status == "OPEN":
            print(f"Port {port}: OPEN")

    open_ports = [
        entry["port"]
        for entry in results
        if entry["status"] == "OPEN"
    ]

    print("\nScan completed.")
    print(f"Total ports scanned: {len(results)}")
    print(f"Open ports: {open_ports}")

    return results


if __name__ == "__main__":
    try:
        start = int(input("Enter starting port: "))
        end = int(input("Enter ending port: "))

        scan_ports(start, end)

    except ValueError as error:
        print("Invalid input:", error)
