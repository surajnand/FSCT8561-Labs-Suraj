
import socket
import logging
import threading

from protocol import send_message, receive_message
from authentication import (
    verify_password,
    verify_totp,
    get_current_totp
)
from pcapanalyzer import analyze_pcap

HOST = "127.0.0.1"
PORT = 9000
MAX_ATTEMPTS = 5

shutdown_event = threading.Event()

# Security logging
logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# Allow the user to type "exit" to stop the server
def shutdown_listener():
    while not shutdown_event.is_set():
        try:
            command = input().strip().lower()

            if command == "exit":
                print("Shutting down Operation Sentinel...")
                shutdown_event.set()
                break

            elif command:
                print("Type 'exit' to stop the server.")

        except EOFError:
            break


# Handle client connections and commands
def handle_client(conn):
    authenticated = False
    password_verified = False
    failed_attempts = 0

    with conn:
        conn.settimeout(1)

        while not shutdown_event.is_set():
            try:
                request = receive_message(conn)
                command = request.get("command")

                # Validate the command
                if not isinstance(command, str):
                    response = {
                        "status": "error",
                        "code": "INVALID_REQUEST"
                    }

                # Initial connection
                elif command == "HELLO":
                    response = {
                        "status": "ok",
                        "message": "Welcome to Operation Sentinel"
                    }

                # Username and password authentication
                elif command == "AUTH_PASSWORD":
                    if authenticated:
                        response = {
                            "status": "error",
                            "code": "ALREADY_AUTHENTICATED"
                        }

                    else:
                        username = request.get("username")
                        password = request.get("password")

                        if verify_password(username, password):
                            password_verified = True

                            # Development-only TOTP display
                            print(
                                "Development TOTP:",
                                get_current_totp()
                            )

                            response = {
                                "status": "OTP_REQUIRED",
                                "message": "Enter your TOTP code"
                            }

                        else:
                            password_verified = False
                            failed_attempts += 1

                            logging.warning(
                                "Failed password authentication"
                            )

                            response = {
                                "status": "error",
                                "code": "AUTH_FAILED"
                            }

                # TOTP verification
                elif command == "AUTH_TOTP":
                    code = request.get("code")

                    if not password_verified:
                        response = {
                            "status": "error",
                            "code": "UNAUTHORIZED"
                        }

                    elif verify_totp(code):
                        authenticated = True
                        password_verified = False

                        logging.info(
                            "Successful MFA authentication"
                        )

                        response = {
                            "status": "ok",
                            "message": "Authentication successful"
                        }

                    else:
                        failed_attempts += 1

                        logging.warning(
                            "Failed TOTP authentication"
                        )

                        response = {
                            "status": "error",
                            "code": "OTP_FAILED"
                        }

                # Protected PCAP analysis
                elif command == "ANALYZE_PCAP":
                    if not authenticated:
                        logging.warning(
                            "Unauthorized PCAP request"
                        )

                        response = {
                            "status": "error",
                            "code": "UNAUTHORIZED"
                        }

                    else:
                        try:
                            results = analyze_pcap()

                            response = {
                                "status": "ok",
                                "message": "PCAP analysis completed",
                                "results": results
                            }

                            logging.info(
                                "PCAP analysis completed"
                            )

                        except (OSError, ValueError) as error:
                            logging.error(
                                "PCAP analysis failed: %s",
                                type(error).__name__
                            )

                            response = {
                                "status": "error",
                                "code": "ANALYSIS_FAILED"
                            }

                # Logout
                elif command == "LOGOUT":
                    authenticated = False
                    password_verified = False

                    logging.info("Client logged out")

                    send_message(conn, {
                        "status": "ok",
                        "message": "Logged out"
                    })
                    break

                # Disconnect
                elif command == "EXIT":
                    send_message(conn, {
                        "status": "ok",
                        "message": "Goodbye"
                    })
                    break

                # Unknown command
                else:
                    response = {
                        "status": "error",
                        "code": "UNKNOWN_COMMAND"
                    }

                # Authentication attempt limit
                if failed_attempts >= MAX_ATTEMPTS:
                    logging.warning(
                        "Authentication attempt limit reached"
                    )

                    send_message(conn, {
                        "status": "error",
                        "code": "RATE_LIMITED"
                    })
                    break

                send_message(conn, response)

            except socket.timeout:
                continue

            except (ConnectionError, OSError, ValueError) as error:
                logging.warning(
                    "Client connection ended: %s",
                    type(error).__name__
                )
                break


# Start TCP server
def main():
    listener = threading.Thread(
        target=shutdown_listener,
        daemon=True
    )
    listener.start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server.bind((HOST, PORT))
        server.listen(5)
        server.settimeout(1)

        print(
            f"Operation Sentinel listening on {HOST}:{PORT}"
        )
        print(
            "Type 'exit' and press Enter to stop the server."
        )

        while not shutdown_event.is_set():
            try:
                conn, addr = server.accept()

                print("Client connected")

                handle_client(conn)

                print("Client disconnected")

            except socket.timeout:
                continue

    print("Server stopped.")


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        shutdown_event.set()
        print("\nServer stopped.")
