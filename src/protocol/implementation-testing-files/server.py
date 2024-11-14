import socket

# Define the server IP and port
server_address = '0.0.0.0'  # Listen on all available interfaces
server_port = 12345  # Replace with the desired port for the server

# Create a TCP/IP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
server_socket.bind((server_address, server_port))

# Listen for incoming connections
server_socket.listen(1)
print(f"Server is listening on {server_address}:{server_port}")

connection, client_address = server_socket.accept()
print(f"Connection from {client_address}")

try:
    while True:
        # Receive data in chunks
        data = connection.recv(1024)
        if data:
            print(f"Received: {data.decode()}")
            response = input("Enter response to send: ")
            connection.sendall(response.encode())
        else:
            print("Client disconnected.")
            break
finally:
    connection.close()
