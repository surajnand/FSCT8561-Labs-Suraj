import nmap
import socket


# Ask for target
target = input("Enter target host: ")


# Resolve hostname/IP
try:
    target_ip = socket.gethostbyname(target)

except socket.gaierror:
    print("Invalid hostname or IP address.")
    exit()


# Ask for ports
try:
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

except ValueError:
    print("Ports must be numbers.")
    exit()


# Validate ports
if start_port < 1 or start_port > 65535:
    print("Start port must be between 1 and 65535.")
    exit()

if end_port < 1 or end_port > 65535:
    print("End port must be between 1 and 65535.")
    exit()

if start_port > end_port:
    print("Start port cannot be greater than end port.")
    exit()

if end_port - start_port > 1000:
    print("Port range is too large.")
    print("Please scan no more than 1000 ports.")
    exit()


# Create Nmap scanner
try:
    scanner = nmap.PortScanner()

except nmap.PortScannerError:
    print("Nmap could not be found.")
    exit()


port_range = str(start_port) + "-" + str(end_port)

print()
print("Target:", target_ip)
print("Scanning TCP ports", port_range + "...")
print()


# Perform scan
try:
    scanner.scan(
        target_ip,
        port_range
    )

except Exception as error:
    print("Scan failed:", error)
    exit()


# Make sure target was returned
if target_ip not in scanner.all_hosts():
    print("No scan results were returned.")
    exit()


# Check for TCP results
if "tcp" not in scanner[target_ip].all_protocols():
    print("No TCP ports were discovered.")
    print()
    print("Scan complete.")
    exit()


tcp_results = scanner[target_ip]["tcp"]


print(
    "PORT".ljust(10),
    "STATE".ljust(10),
    "SERVICE"
)


# Display discovered ports
for port in sorted(tcp_results.keys()):

    state = tcp_results[port]["state"]

    service = tcp_results[port].get(
        "name",
        "unknown"
    )

    if service == "":
        service = "unknown"

    print(
        str(port).ljust(10),
        state.ljust(10),
        service
    )


print()
print("Scan complete.")