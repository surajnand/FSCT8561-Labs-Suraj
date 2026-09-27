import socket

TARGET = "127.0.0.1"
PORT = 12345

scanner_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

scanner_socket.settimeout(0.5)

result = scanner_socket.connect_ex(
    (TARGET, PORT)
)

if result == 0:
    print("Port", PORT, "is OPEN")
else:
    print("Port", PORT, "is not open")

scanner_socket.close()