import socket
import threading

HOST = "127.0.0.1"
PORT = 5000


def receive_messages():
    while True:
        try:
            message = client.recv(1024)

            if not message:
                break

            print("\n" + message.decode())

        except:
            break


# Create client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((HOST, PORT))

print("Connected to server.")

# Ask user for username
username = input("Enter username: ")

# Send username to server
client.send(("HELLO|" + username).encode())


# Start a thread that listens for incoming messages
receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()


print("You can now send messages.")
print("Type EXIT to disconnect.")


while True:
    message = input("> ")

    if message.upper() == "EXIT":
        client.send("EXIT".encode())
        break

    client.send(("MSG|" + message).encode())


client.close()

print("Disconnected from server.")