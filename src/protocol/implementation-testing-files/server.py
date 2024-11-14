import socket
import threading

# Define the server IP and port
server_address = '0.0.0.0'  # Listen on all available interfaces
server_port = 12345  # Replace with the desired server port

# Create a TCP/IP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_address, server_port))
server_socket.listen(1)
print(f"Server is listening on {server_address}:{server_port}")

connection, client_address = server_socket.accept()
print(f"Connection from {client_address}")

# Function to receive messages from the client
def receive_messages():
    while True:
        data = connection.recv(1024)
        if data:
            print(f"Client: {data.decode()}")
        else:
            print("Client disconnected.")
            break

# Function to send messages to the client
def send_messages():
    while True:
        message = input("Enter message to send: ")
        connection.sendall(message.encode())

# Start threads for sending and receiving messages
receive_thread = threading.Thread(target=receive_messages)
send_thread = threading.Thread(target=send_messages)
receive_thread.start()
send_thread.start()

receive_thread.join()
send_thread.join()
connection.close()
