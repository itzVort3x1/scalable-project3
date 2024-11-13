import struct
import socket
import zlib
import logging
import time
import json
import select
import sys
from protocol.necessary_headers import Bob2Headers
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

P = 23  # Diffie-Hellman prime number
G = 5   # Diffie-Hellman generator

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Bob2Protocol:
    def __init__(self, version_major=0, version_minor=0, host="127.0.0.1", port=12345, role="client"):
        self.version_major = version_major
        self.version_minor = version_minor
        self.server_host = host
        self.server_port = port
        self.role = role  # Add role to indicate "client" or "server"
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.shared_key = None

    def start_server(self):
        self.server_socket.bind((self.server_host, self.server_port))
        self.server_socket.listen(1)
        logging.info(f"Server listening on {self.server_port}")
        client_socket, addr = self.server_socket.accept()
        logging.info(f"Server connected to {addr}")
        self.perform_handshake(client_socket=client_socket, is_server=True)
        self.handle_communication(client_socket)

    def connect_to_server(self):
        self.client_socket.connect((self.server_host, self.server_port))
        logging.info(f"Connected to server at {self.server_host}:{self.server_port}")
        self.perform_handshake(client_socket=self.client_socket, is_server=False)
        self.handle_communication(self.client_socket)

    def generate_keys(self):
        private_key = random.randint(1, P - 1)
        public_key = pow(G, private_key, P)
        logging.info(f"Generated keys: Private key (hidden), Public key: {public_key}")
        return private_key, public_key

    def perform_handshake(self, client_socket, is_server):
        if is_server:
            logging.info("Server: Generating keys for handshake.")
            server_private_key, server_public_key = self.generate_keys()
            client_socket.sendall(str(server_public_key).encode())
            logging.info("Server: Sent public key to client.")
            client_public_key = int(client_socket.recv(1024).decode())
            logging.info("Server: Received public key from client.")

            shared_secret = pow(client_public_key, server_private_key, P)
            self.shared_key = sha256(str(shared_secret).encode()).digest()
            logging.info("Server: Shared secret established.")
        else:
            logging.info("Client: Generating keys for handshake.")
            client_private_key, client_public_key = self.generate_keys()
            server_public_key = int(client_socket.recv(1024).decode())
            logging.info("Client: Received public key from server.")
            client_socket.sendall(str(client_public_key).encode())
            logging.info("Client: Sent public key to server.")

            shared_secret = pow(server_public_key, client_private_key, P)
            self.shared_key = sha256(str(shared_secret).encode()).digest()
            logging.info("Client: Shared secret established.")

    def encrypt_message(self, message):
        cipher = AES.new(self.shared_key, AES.MODE_CBC)
        iv = cipher.iv
        cipher_text = cipher.encrypt(pad(message.encode(), AES.block_size))
        logging.info(f"Message encrypted. IV: {iv.hex()}, Cipher text: {cipher_text.hex()}")
        return iv + cipher_text

    def decrypt_message(self, iv_cipher_text):
        iv = iv_cipher_text[:16]
        cipher_text = iv_cipher_text[16:]
        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(cipher_text), AES.block_size).decode('utf-8')
        logging.info(f"Message decrypted. IV: {iv.hex()}, Decrypted text: {decrypted_message}")
        return decrypted_message

    def send_message(self, client_socket, message_dict):
        try:
            message_json = json.dumps(message_dict)
            encrypted_message = self.encrypt_message(message_json)
            client_socket.sendall(encrypted_message)
            logging.info(f"Message sent from {self.role}: {message_json}")
        except Exception as e:
            logging.error(f"Failed to send message from {self.role}: {e}")

    def receive_message(self, client_socket):
        try:
            iv_cipher_text = client_socket.recv(1024)
            if iv_cipher_text:
                decrypted_message = self.decrypt_message(iv_cipher_text)
                message_dict = json.loads(decrypted_message)
                logging.info(f"Message received by {self.role}: {message_dict}")
                return message_dict
            else:
                logging.warning("No message received or connection closed.")
                return None
        except Exception as e:
            logging.error(f"Failed to receive message: {e}")
            return None

    def handle_communication(self, client_socket):
        logging.info("Starting continuous communication.")
        client_socket.setblocking(0)  # Make socket non-blocking for select-based handling

        while True:
            readable, _, _ = select.select([client_socket, sys.stdin], [], [])

            for s in readable:
                if s == client_socket:
                    # Receiving message from the socket
                    message = self.receive_message(client_socket)
                    if message:
                        logging.info(f"Message from {'server' if self.role == 'client' else 'client'}: {message}")
                    else:
                        logging.info("Connection closed by the other party.")
                        return

                elif s == sys.stdin:
                    # Reading user input
                    message_content = input("Type a message to send (or 'exit' to quit): ")
                    if message_content.lower() == "exit":
                        logging.info("Exiting communication.")
                        client_socket.close()
                        return

                    # Prepare message dictionary
                    message_dict = {
                        'version_major': self.version_major,
                        'version_minor': self.version_minor,
                        'message_type': 0,
                        'dest_ipv6': '2001:db8:85a3::8a2e:370:7334',
                        'dest_port': self.server_port,
                        'source_ipv6': '2001:db8:85a3::8a2e:370:1111',
                        'source_port': self.server_port,
                        'sequence_number': 1,
                        'timestamp': int(time.time()),
                        'message_length': len(message_content),
                        'checksum': zlib.crc32(message_content.encode('utf-8')),
                        'message_content': message_content
                    }
                    self.send_message(client_socket, message_dict)
