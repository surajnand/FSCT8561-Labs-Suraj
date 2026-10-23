
import json
import struct

MAX_MESSAGE_SIZE = 64 * 1024


def receive_exact(sock, length):
    data = bytearray()

    while len(data) < length:
        chunk = sock.recv(length - len(data))

        if not chunk:
            raise ConnectionError("Connection closed")

        data.extend(chunk)

    return bytes(data)


def send_message(sock, message):
    payload = json.dumps(message).encode("utf-8")

    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError("Message too large")

    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def receive_message(sock):
    header = receive_exact(sock, 4)
    length = struct.unpack("!I", header)[0]

    if length == 0 or length > MAX_MESSAGE_SIZE:
        raise ValueError("Invalid message length")

    payload = receive_exact(sock, length)

    try:
        message = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Invalid JSON message")

    if not isinstance(message, dict):
        raise ValueError("Message must be a JSON object")

    return message
