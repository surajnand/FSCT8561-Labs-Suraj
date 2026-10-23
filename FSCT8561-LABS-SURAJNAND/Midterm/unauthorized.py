
import socket
import json

from protocol import send_message, receive_message

HOST = "127.0.0.1"
PORT = 9000

print("===== TC-03: Unauthorized Command Test =====")

try:
    with socket.create_connection((HOST, PORT), timeout=5) as client:
        client.settimeout(5)

        # Attempt PCAP analysis without authentication
        send_message(client, {
            "command": "ANALYZE_PCAP"
        })

        response = receive_message(client)

        print("Command: ANALYZE_PCAP")
        print("Authentication: Not performed")
        print("Server response:")
        print(json.dumps(response, indent=4))

        if (
            response.get("status") == "error"
            and response.get("code") == "UNAUTHORIZED"
        ):
            print("\nTEST RESULT: PASS")
        else:
            print("\nTEST RESULT: FAIL")

except (OSError, ValueError) as error:
    print("Test error:", error)
    print("TEST RESULT: FAIL")
