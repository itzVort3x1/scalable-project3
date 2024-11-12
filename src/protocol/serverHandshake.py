import socket
import threading
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

P = 23  # Diffie-Hellman prime number
G = 5   # Diffie-Hellman generator

class PersistentServer:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.shared_key = None

    def start_server(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        print(f"Server listening on {self.port}")
        client_socket, addr = self.server_socket.accept()
        print(f"Connected to {addr}")

        self.perform_handshake(client_socket)
        threading.Thread(target=self.receive_messages, args=(client_socket,), daemon=True).start()

        # Loop to allow the server to continuously send messages
        while True:
            message = input("Server: ")
            self.send_encrypted_message(client_socket, message)

    def generate_keys(self):
        private_key = random.randint(1, P - 1)
        public_key = pow(G, private_key, P)
        return private_key, public_key

    def perform_handshake(self, client_socket):
        server_private_key, server_public_key = self.generate_keys()
        client_socket.sendall(str(server_public_key).encode())

        client_public_key = int(client_socket.recv(1024).decode())
        shared_secret = pow(client_public_key, server_private_key, P)
        self.shared_key = sha256(str(shared_secret).encode()).digest()
        print("Shared secret established.")

    def send_encrypted_message(self, client_socket, message):
        cipher = AES.new(self.shared_key, AES.MODE_CBC)
        cipher_text = cipher.encrypt(pad(message.encode(), AES.block_size))
        client_socket.sendall(cipher.iv + cipher_text)

    def receive_messages(self, client_socket):
        while True:
            iv_cipher_text = client_socket.recv(1024)
            if not iv_cipher_text:
                break
            iv = iv_cipher_text[:16]
            cipher_text = iv_cipher_text[16:]
            cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
            decrypted_message = unpad(cipher.decrypt(cipher_text), AES.block_size)
            print("Client:", decrypted_message.decode())

# Run server
server = PersistentServer()
server.start_server()
