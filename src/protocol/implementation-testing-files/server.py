import socket

# Define the server address and port
server_address = '0.0.0.0'  # Listen on all available interfaces
server_port = 12345  # You can use any available port

# Create a TCP/IP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
server_socket.bind((server_address, server_port))

# Listen for incoming connections (backlog parameter 1 to allow one connection at a time)
server_socket.listen(1)
print(f"Server is listening on {server_address}:{server_port}")

while True:
    # Accept a connection
    connection, client_address = server_socket.accept()
    try:
        print(f"Connection from {client_address}")

        # Receive data in small chunks and respond
        while True:
            data = connection.recv(1024)
            if data:
                print(f"Received: {data.decode()}")
                connection.sendall(b"Message received!")
            else:
                break
    finally:
        # Clean up the connection
        connection.close()
