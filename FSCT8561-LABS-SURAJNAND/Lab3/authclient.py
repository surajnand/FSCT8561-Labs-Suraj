import socket
from getpass import getpass

HOST = "127.0.0.1"
PORT = 12345

client_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client_socket.connect((HOST, PORT))

print("Connected to authentication server")

connected = True

while connected:

    username = input("Enter your username: ")
    password = getpass("Enter your password: ")

    auth_message = (
        "AUTH|" + username + "|" + password
    )

    client_socket.send(
        auth_message.encode()
    )

    response = client_socket.recv(1024)

    if not response:
        print("Server closed the connection")
        break

    server_response = response.decode()

    print("Server:", server_response)

    # Password was correct, so ask for OTP
    if server_response == "OTP_REQUIRED":

        otp = input("Enter your OTP: ")

        otp_message = "OTP|" + otp

        client_socket.send(
            otp_message.encode()
        )

        response = client_socket.recv(1024)

        if not response:
            print("Server closed the connection")
            break

        server_response = response.decode()

        print("Server:", server_response)

        if server_response == "ACCESS_GRANTED":
            connected = False

        elif server_response.startswith(
            "ACCESS_DENIED|Too many failed attempts"
        ):
            print("Authentication blocked.")
            connected = False

        elif server_response == "ACCESS_DENIED":
            print("Authentication failed. Try again.")

    # Password/username was incorrect
    elif server_response == "ACCESS_DENIED":

        print("Authentication failed. Try again.")

    # Maximum failures reached
    elif server_response.startswith(
        "ACCESS_DENIED|Too many failed attempts"
    ):

        print("Authentication blocked.")
        connected = False

    # Handle protocol errors
    elif server_response.startswith("ERROR|"):

        print("Authentication error.")
        connected = False


client_socket.close()

print("Disconnected")