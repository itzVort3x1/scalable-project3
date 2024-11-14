import socket

# Define the server IP and port
server_address = 'SERVER_IP_ADDRESS'  # Replace with server's IP address
server_port = 12345  # Replace with the desired server port
client_port = 54321  # Replace with the desired client port

# Create a TCP/IP socket and bind to a specific client port
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.bind(('', client_port))  # Bind to the specified client port

# Connect to the server
client_socket.connect((server_address, server_port))
print(f"Connected to server at {server_address}:{server_port} from port {client_port}")

try:
    while True:
        # Send message
        message = input("Enter message to send: ")
        client_socket.sendall(message.encode())
        
        # Wait for a response
        data = client_socket.recv(1024)
        print(f"Received: {data.decode()}")
finally:
    client_socket.close()
