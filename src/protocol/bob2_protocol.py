# protocol.py
import struct
import socket
import logging
import time
import json
import select
import sys
import zlib
from protocol.handshake import Handshake

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Bob2Protocol:
    def __init__(self, version_major=0, version_minor=0, host="127.0.0.1", port=12345, mode="", dest_ipv6="::1", dest_port=12345, source_ipv6="::1", source_port=12345):
        self.version_major = version_major
        self.version_minor = version_minor
        self.server_host = host
        self.server_port = port
        self.dest_ipv6 = dest_ipv6
        self.dest_port = dest_port
        self.source_ipv6 = source_ipv6
        self.source_port = source_port
        self.role = mode  # Add role to indicate "client" or "server"
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.handshake = Handshake()

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

    def perform_handshake(self, client_socket, is_server):
        if is_server:
            logging.info("Server: Generating keys for handshake.")
            server_private_key, server_public_key = self.handshake.generate_keys()
            client_socket.sendall(str(server_public_key).encode())
            logging.info("Server: Sent public key to client.")
            client_public_key = int(client_socket.recv(1024).decode())
            logging.info("Server: Received public key from client.")
            self.handshake.establish_shared_key(client_public_key, server_private_key)
            logging.info("Server: Shared secret established.")
        else:
            logging.info("Client: Generating keys for handshake.")
            client_private_key, client_public_key = self.handshake.generate_keys()
            server_public_key = int(client_socket.recv(1024).decode())
            logging.info("Client: Received public key from server.")
            client_socket.sendall(str(client_public_key).encode())
            logging.info("Client: Sent public key to server.")
            self.handshake.establish_shared_key(server_public_key, client_private_key)
            logging.info("Client: Shared secret established.")

    def send_message(self, client_socket, message_dict):
        try:
            message_json = json.dumps(message_dict)
            encrypted_message = self.handshake.encrypt_message(message_json)
            client_socket.sendall(encrypted_message)
            logging.info(f"Message sent from {self.role}: {message_json}")
        except Exception as e:
            logging.error(f"Failed to send message from {self.role}: {e}")

    def receive_message(self, client_socket):
        try:
            iv_cipher_text = client_socket.recv(1024)
            if iv_cipher_text:
                decrypted_message = self.handshake.decrypt_message(iv_cipher_text)
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
        client_socket.setblocking(0)

        while True:
            readable, _, _ = select.select([client_socket, sys.stdin], [], [])

            for s in readable:
                if s == client_socket:
                    message = self.receive_message(client_socket)
                    if message:
                        logging.info(f"Message from {'server' if self.role == 'client' else 'client'}: {message}")
                    else:
                        logging.info("Connection closed by the other party.")
                        return

                elif s == sys.stdin:
                    message_content = input("Type a message to send (or 'exit' to quit): ")
                    if message_content.lower() == "exit":
                        logging.info("Exiting communication.")
                        client_socket.close()
                        return

                    message_dict = {
                        'version_major': self.version_major,
                        'version_minor': self.version_minor,
                        'message_type': 0,
                        'dest_ipv6': self.dest_ipv6,
                        'dest_port': self.dest_port,
                        'source_ipv6': self.source_ipv6,
                        'source_port': self.source_port,
                        'sequence_number': 1,
                        'timestamp': int(time.time()),
                        'message_length': len(message_content),
                        'checksum': zlib.crc32(message_content.encode('utf-8')),
                        'message_content': message_content
                    }
                    self.send_message(client_socket, message_dict)