import socket
import hashlib
import pyotp

HOST = "127.0.0.1"
PORT = 12345

MAX_FAILED_ATTEMPTS = 3


def hash_password(password):
    return hashlib.sha256(
        password.encode()
    ).hexdigest()


def verify_password(password, stored_hash):
    entered_hash = hash_password(password)
    return entered_hash == stored_hash


def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)


# Create Alice's account
alice_secret = pyotp.random_base32()

users = {
    "alice": {
        "password_hash": hash_password("Cyber123!"),
        "totp_secret": alice_secret
    }
}

print("Alice's TOTP secret:")
print(alice_secret)


# Create server socket
server_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("Server is waiting for a connection...")


# Accept one client
client_socket, client_address = server_socket.accept()

print("Connected by:", client_address)


# Authentication state
password_verified = False
authenticated_user = None
failed_attempts = 0
connected = True


while connected:

    try:
        data = client_socket.recv(1024)

        if not data:
            print("Client disconnected")
            break

        message = data.decode()

        print("Received:", message)

        parts = message.split("|")
        command = parts[0]


        # ------------------------
        # AUTH
        # ------------------------

        if command == "AUTH":

            if len(parts) != 3:
                client_socket.send(
                    "ERROR|Invalid AUTH format".encode()
                )
                continue

            username = parts[1]
            password = parts[2]


            # Check if already blocked
            if failed_attempts >= MAX_FAILED_ATTEMPTS:

                client_socket.send(
                    "ACCESS_DENIED|Too many failed attempts".encode()
                )

                print("Authentication blocked.")

                break


            # Check username
            if username not in users:

                failed_attempts += 1

                password_verified = False
                authenticated_user = None

                print(
                    "Failed attempts:",
                    failed_attempts
                )

                client_socket.send(
                    "ACCESS_DENIED".encode()
                )

                if failed_attempts >= MAX_FAILED_ATTEMPTS:
                    print("Too many failed attempts.")
                    print("Authentication blocked.")
                    break

                continue


            stored_hash = users[
                username
            ]["password_hash"]


            # Check password
            if verify_password(
                password,
                stored_hash
            ):

                password_verified = True
                authenticated_user = username

                print(
                    "Password accepted for:",
                    username
                )

                current_otp = pyotp.TOTP(
                    users[username]["totp_secret"]
                ).now()

                print(
                    "Current OTP:",
                    current_otp
                )

                client_socket.send(
                    "OTP_REQUIRED".encode()
                )

            else:

                failed_attempts += 1

                password_verified = False
                authenticated_user = None

                print("Password rejected")
                print(
                    "Failed attempts:",
                    failed_attempts
                )

                client_socket.send(
                    "ACCESS_DENIED".encode()
                )

                if failed_attempts >= MAX_FAILED_ATTEMPTS:
                    print("Too many failed attempts.")
                    print("Authentication blocked.")
                    break


        # ------------------------
        # OTP
        # ------------------------

        elif command == "OTP":

            if len(parts) != 2:
                client_socket.send(
                    "ERROR|Invalid OTP format".encode()
                )
                continue


            # Password must be verified first
            if not password_verified:

                client_socket.send(
                    "ACCESS_DENIED".encode()
                )

                continue


            otp = parts[1]

            secret = users[
                authenticated_user
            ]["totp_secret"]


            if verify_otp(
                secret,
                otp
            ):

                print(
                    "Access granted to:",
                    authenticated_user
                )

                # Successful authentication
                # resets failed attempts
                failed_attempts = 0

                client_socket.send(
                    "ACCESS_GRANTED".encode()
                )

                connected = False

            else:

                failed_attempts += 1

                print("OTP rejected")
                print(
                    "Failed attempts:",
                    failed_attempts
                )

                client_socket.send(
                    "ACCESS_DENIED".encode()
                )

                # Return to password stage
                password_verified = False
                authenticated_user = None

                if failed_attempts >= MAX_FAILED_ATTEMPTS:

                    print("Too many failed attempts.")
                    print("Authentication blocked.")

                    break


        # ------------------------
        # Unknown command
        # ------------------------

        else:

            client_socket.send(
                "ERROR|Unknown command".encode()
            )


    except ConnectionResetError:

        print("Connection reset by client")
        break


client_socket.close()
server_socket.close()

print("Server closed")