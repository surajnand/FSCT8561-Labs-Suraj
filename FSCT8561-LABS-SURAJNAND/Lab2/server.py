import socket
import select

HOST = "127.0.0.1"
PORTS = [22, 53, 80]

server_sockets = []

try:
    # Create a listening socket for each test port
    for port in PORTS:

        server_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server_socket.bind((HOST, port))
        server_socket.listen(5)
        server_socket.setblocking(False)

        server_sockets.append(server_socket)

        print("Listening on test port", port)

    print()
    print("Test server is running.")
    print("Open test ports:", PORTS)
    print("Press Ctrl+C to stop the server.")
    print()

    while True:

        readable, _, _ = select.select(
            server_sockets,
            [],
            [],
            1
        )

        for server_socket in readable:

            client_socket = None

            try:
                client_socket, client_address = (
                    server_socket.accept()
                )

                port = server_socket.getsockname()[1]

                print(
                    "Connection received on port",
                    port
                )

                client_socket.settimeout(0.5)

                try:
                    # Receive data if the scanner sends any,
                    # but do not display Nmap probe data.
                    client_socket.recv(1024)

                except socket.timeout:
                    pass

                except ConnectionResetError:
                    pass

            except OSError:
                pass

            finally:
                if client_socket is not None:
                    client_socket.close()


except KeyboardInterrupt:
    print()
    print("Stopping test server...")


finally:
    for server_socket in server_sockets:
        server_socket.close()

    print("Server closed.")