

import socket
import getpass
import json

from protocol import send_message, receive_message
from portscanner import scan_ports
from httpchecker import check_http_security

HOST = "127.0.0.1"
PORT = 9000


def display_response(response):
    """Display server responses in a readable format."""
    print(json.dumps(response, indent=4))


def main():
    try:
        # Connect to Operation Sentinel server
        with socket.create_connection(
            (HOST, PORT),
            timeout=5
        ) as client:

            client.settimeout(60)

            print("\n===== Operation Sentinel Client =====")

            # Initial connection
            send_message(client, {
                "command": "HELLO"
            })

            response = receive_message(client)
            display_response(response)

            # Username and password authentication
            print("\n===== Login =====")

            username = input("Username: ")
            password = getpass.getpass("Password: ")

            send_message(client, {
                "command": "AUTH_PASSWORD",
                "username": username,
                "password": password
            })

            response = receive_message(client)
            display_response(response)

            if response.get("status") != "OTP_REQUIRED":
                print("Password authentication failed.")
                return

            # TOTP multi-factor authentication
            code = input("Enter 6-digit TOTP code: ")

            send_message(client, {
                "command": "AUTH_TOTP",
                "code": code
            })

            response = receive_message(client)
            display_response(response)

            if response.get("status") != "ok":
                print("MFA authentication failed.")
                return

            print("\nAuthentication successful!")

            # Main menu
            while True:
                print("\n===== Operation Sentinel Menu =====")
                print("1. Analyze PCAP")
                print("2. Scan Local TCP Ports")
                print("3. Check HTTP Security")
                print("4. Logout")
                print("5. Exit")

                choice = input("Choose an option: ").strip()

                # Protected PCAP analysis through server
                if choice == "1":
                    print("\nRunning PCAP analysis...")

                    send_message(client, {
                        "command": "ANALYZE_PCAP"
                    })

                    response = receive_message(client)
                    display_response(response)

                # Local TCP port scanner
                elif choice == "2":
                    try:
                        start_port = int(
                            input("Enter starting port: ")
                        )

                        end_port = int(
                            input("Enter ending port: ")
                        )

                        scan_ports(start_port, end_port)

                    except ValueError as error:
                        print("Invalid input:", error)

                # Local HTTP security checker
                elif choice == "3":
                    print("\nStarting HTTP security assessment...")

                    results = check_http_security()

                    print(
                        f"\nTotal endpoints assessed: {len(results)}"
                    )

                # Logout
                elif choice == "4":
                    send_message(client, {
                        "command": "LOGOUT"
                    })

                    response = receive_message(client)
                    display_response(response)

                    print("You have been logged out.")
                    break

                # Exit application
                elif choice == "5":
                    send_message(client, {
                        "command": "EXIT"
                    })

                    response = receive_message(client)
                    display_response(response)

                    print("Operation Sentinel client closed.")
                    break

                else:
                    print("Invalid option. Please choose 1-5.")

    except ConnectionRefusedError:
        print(
            "Connection refused. Make sure server.py is running."
        )

    except socket.timeout:
        print("Connection timed out.")

    except (OSError, ConnectionError, ValueError) as error:
        print("Connection error:", error)

    except (KeyboardInterrupt, EOFError):
        print("\nClient stopped by user.")


if __name__ == "__main__":
    main()
