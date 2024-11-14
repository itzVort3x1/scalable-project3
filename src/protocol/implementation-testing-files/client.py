import socket
import threading

# Server IP and port
server_ip = "192.168.1.100"  # Replace with the server's IP address on LAN
server_port = 12345

# Client's IP and port (optional)
client_ip = "0.0.0.0"  # Bind to all interfaces
client_port = 54321  # Optional specific source port

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.bind((client_ip, client_port))
client_socket.connect((server_ip, server_port))
print(f"Connected to server at {server_ip}:{server_port} from client port {client_port}")

# Function to handle receiving messages from the server
def receive_messages():
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                print("Server disconnected.")
                break
            print(f"Server: {message}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Function to handle sending messages to the server
def send_messages():
    while True:
        message = input("Client: ")
        client_socket.sendall(message.encode())

# Start threads for sending and receiving
receive_thread = threading.Thread(target=receive_messages)
send_thread = threading.Thread(target=send_messages)

receive_thread.start()
send_thread.start()

receive_thread.join()
send_thread.join()

client_socket.close()
