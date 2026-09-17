import socket
import threading

HOST = "127.0.0.1"
PORT = 5000

# Stores each connected client and their username
clients = {}

# Prevents multiple threads from changing clients at the same time
clients_lock = threading.Lock()


def handle_client(client_socket, address):
    username = None

    print("New connection from:", address)

    try:
        while True:
            data = client_socket.recv(1024)

            # Client disconnected unexpectedly
            if not data:
                break

            message = data.decode()

            # Client sends username
            if message.startswith("HELLO|"):
                username = message.split("|", 1)[1]

                with clients_lock:
                    clients[client_socket] = username

                print(username, "connected.")

            # Client sends a message
            elif message.startswith("MSG|"):
                text = message.split("|", 1)[1]

                print(username + ": " + text)

                outgoing_message = username + ": " + text

                # Get a copy of connected clients
                with clients_lock:
                    connected_clients = list(clients.keys())

                # Send message to everyone except sender
                for other_client in connected_clients:
                    if other_client != client_socket:
                        try:
                            other_client.send(outgoing_message.encode())
                        except:
                            pass

            # Client wants to leave
            elif message == "EXIT":
                print(username, "requested to disconnect.")
                break

    except ConnectionResetError:
        print("Client disconnected unexpectedly:", address)

    except Exception as error:
        print("Error:", error)

    finally:
        # Remove client from dictionary
        with clients_lock:
            if client_socket in clients:
                del clients[client_socket]

        client_socket.close()

        if username:
            print(username, "disconnected.")


# Create server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((HOST, PORT))
server.listen()

print("Server is running on", HOST, "port", PORT)
print("Waiting for clients...")


# Keep accepting new clients
while True:
    client_socket, address = server.accept()

    # Give each client their own thread
    client_thread = threading.Thread(
        target=handle_client,
        args=(client_socket, address)
    )

    client_thread.start()