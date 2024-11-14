import socket
import threading

# Server setup
server_ip = "0.0.0.0"  # Bind to all available network interfaces
server_port = 12345
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_ip, server_port))
server_socket.listen(1)

print(f"Server listening on {server_ip}:{server_port}...")

# Wait for client connection
client_socket, client_address = server_socket.accept()
print(f"Connected to {client_address}")

# Function to handle receiving messages from the client
def receive_messages():
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                print("Client disconnected.")
                break
            print(f"Client: {message}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Function to handle sending messages to the client
def send_messages():
    while True:
        message = input("Server: ")
        client_socket.sendall(message.encode())

# Start threads for sending and receiving
receive_thread = threading.Thread(target=receive_messages)
send_thread = threading.Thread(target=send_messages)

receive_thread.start()
send_thread.start()

receive_thread.join()
send_thread.join()

client_socket.close()
server_socket.close()
