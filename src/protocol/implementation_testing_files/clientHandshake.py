import socket
import threading
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

P = 23  # Diffie-Hellman prime number
G = 5   # Diffie-Hellman generator

class PersistentClient:
    def __init__(self, server_host='127.0.0.1', server_port=12345):
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.shared_key = None

    def connect_to_server(self):
        self.client_socket.connect((self.server_host, self.server_port))
        print(f"Connected to server at {self.server_host}:{self.server_port}")
        self.perform_handshake()
        
        threading.Thread(target=self.receive_messages, daemon=True).start()

        # Loop to allow the client to continuously send messages
        while True:
            message = input("Client: ")
            self.send_encrypted_message(message)

    def generate_keys(self):
        private_key = random.randint(1, P - 1)
        public_key = pow(G, private_key, P)
        return private_key, public_key

    def perform_handshake(self):
        client_private_key, client_public_key = self.generate_keys()
        server_public_key = int(self.client_socket.recv(1024).decode())
        self.client_socket.sendall(str(client_public_key).encode())
        shared_secret = pow(server_public_key, client_private_key, P)
        self.shared_key = sha256(str(shared_secret).encode()).digest()
        print("Shared secret established.")

    def send_encrypted_message(self, message):
        cipher = AES.new(self.shared_key, AES.MODE_CBC)
        cipher_text = cipher.encrypt(pad(message.encode(), AES.block_size))
        self.client_socket.sendall(cipher.iv + cipher_text)

    def receive_messages(self):
        while True:
            iv_cipher_text = self.client_socket.recv(1024)
            if not iv_cipher_text:
                break
            iv = iv_cipher_text[:16]
            cipher_text = iv_cipher_text[16:]
            cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
            decrypted_message = unpad(cipher.decrypt(cipher_text), AES.block_size)
            print("Server:", decrypted_message.decode())

# Run client
client = PersistentClient()
client.connect_to_server()
