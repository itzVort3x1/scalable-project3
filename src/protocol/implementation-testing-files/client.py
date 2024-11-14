import socket

# Define the server address and port
server_address = 'SERVER_IP_ADDRESS'  # Replace with server's IP address
server_port = 12345

# Create a TCP/IP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the server's address and port
client_socket.connect((server_address, server_port))

try:
    # Send data
    message = "Hello from the client!"
    print(f"Sending: {message}")
    client_socket.sendall(message.encode())

    # Wait for a response
    data = client_socket.recv(1024)
    print(f"Received: {data.decode()}")

finally:
    # Clean up the connection
    client_socket.close()
