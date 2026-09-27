import socket


def scan_port(target, port):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(0.5)

    try:
        result = sock.connect_ex(
            (target, port)
        )

        if result == 0:
            return True
        else:
            return False

    finally:
        sock.close()


def get_service(port):
    try:
        return socket.getservbyport(
            port,
            "tcp"
        )

    except OSError:
        return "unknown"


# Ask for target host
target = input("Enter target host: ")


# Resolve target
try:
    target_ip = socket.gethostbyname(target)

except socket.gaierror:
    print("Invalid hostname or IP address.")
    exit()


# Ask for port range
try:
    start_port = int(
        input("Enter start port: ")
    )

    end_port = int(
        input("Enter end port: ")
    )

except ValueError:
    print("Ports must be numbers.")
    exit()


# Validate start port
if start_port < 1 or start_port > 65535:
    print(
        "Start port must be between 1 and 65535."
    )
    exit()


# Validate end port
if end_port < 1 or end_port > 65535:
    print(
        "End port must be between 1 and 65535."
    )
    exit()


# Make sure range is in correct order
if start_port > end_port:
    print(
        "Start port cannot be greater than end port."
    )
    exit()


# Limit size of scan
if end_port - start_port > 1000:
    print("Port range is too large.")
    print(
        "Please scan no more than 1000 ports."
    )
    exit()


# Display scan information
print()
print("Target:", target_ip)

print(
    "Scanning TCP ports",
    str(start_port) + "-" + str(end_port) + "..."
)

print()


open_ports = []


# Scan ports
for port in range(
    start_port,
    end_port + 1
):

    if scan_port(target_ip, port):

        service = get_service(port)

        open_ports.append(
            (port, service)
        )


# Display results
if len(open_ports) > 0:

    print(
        "PORT".ljust(10),
        "STATE".ljust(10),
        "SERVICE"
    )

    for port, service in open_ports:

        print(
            str(port).ljust(10),
            "open".ljust(10),
            service
        )

    print()
    print("Scan complete.")

    print(
        len(open_ports),
        "open port(s) found."
    )

else:

    print(
        "No open ports found in the selected range."
    )

    print()
    print("Scan complete.")