import socket
import threading

# Define the server IP and port
server_address = 'SERVER_IP_ADDRESS'  # Replace with server's IP address
server_port = 12345  # Replace with the desired server port
client_port = 54321  # Replace with the desired client port

# Create a TCP/IP socket and bind to the specific client port
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.bind(('', client_port))
client_socket.connect((server_address, server_port))
print(f"Connected to server at {server_address}:{server_port} from port {client_port}")

# Function to receive messages from the server
def receive_messages():
    while True:
        data = client_socket.recv(1024)
        if data:
            print(f"Server: {data.decode()}")
        else:
            print("Server disconnected.")
            break

# Function to send messages to the server
def send_messages():
    while True:
        message = input("Enter message to send: ")
        client_socket.sendall(message.encode())

# Start threads for sending and receiving messages
receive_thread = threading.Thread(target=receive_messages)
send_thread = threading.Thread(target=send_messages)
receive_thread.start()
send_thread.start()

receive_thread.join()
send_thread.join()
client_socket.close()
