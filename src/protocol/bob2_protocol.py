# src/protocol/bob2_protocol.py

import struct
import socket
import zlib
from protocol.necessary_headers import Bob2Headers
import socket
import threading
import random
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

P = 23  # Diffie-Hellman prime number
G = 5   # Diffie-Hellman generator

class Bob2Protocol:
    def __init__(self, version_major=0, version_minor=0, host="127.0.0.1", port=12345):
        self.version_major = version_major
        self.version_minor = version_minor
        self.server_host = host
        self.server_port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.shared_key = None

    def start_server(self):
        self.server_socket.bind((self.server_host, self.server_port))
        self.server_socket.listen(1)
        print(f"Server listening on {self.server_port}")
        client_socket, addr = self.server_socket.accept()
        print(f"Connected to {addr}")
        self.perform_handshake()

    def connect_to_server(self):
        self.client_socket.connect((self.server_host, self.server_port))
        print(f"Connected to server at {self.server_host}:{self.server_port}")
        self.perform_handshake()

    def generate_keys(self):
        private_key = random.randint(1, P - 1)
        public_key = pow(G, private_key, P)
        return private_key, public_key

    def perform_handshake(self):
        client_private_key, client_public_key = self.generate_keys()
        print(client_private_key, client_public_key)
        server_public_key = int(self.client_socket.recv(1024).decode())
        print("Generated client keys.")
        self.client_socket.sendall(str(client_public_key).encode())
        
        shared_secret = pow(server_public_key, client_private_key, P)
        self.shared_key = sha256(str(shared_secret).encode()).digest()
        print("Shared secret established.")

    def build_message(self, message_type, dest_ipv6, dest_port, source_ipv6, source_port, sequence_number, message_content):
        # Create the header using Bob2Headers
        header = Bob2Headers(
            version_major=self.version_major,
            version_minor=self.version_minor,
            message_type=message_type,
            dest_ipv6=dest_ipv6,
            dest_port=dest_port,
            source_ipv6=source_ipv6,
            source_port=source_port,
            sequence_number=sequence_number
        ).build_header()

        # Calculate checksum
        checksum = zlib.crc32(message_content.encode('utf-8'))
        checksum_bytes = struct.pack('!I', checksum)

        # Build the full message
        message_length = len(message_content)
        length_bytes = message_length.to_bytes(5, byteorder='big')

        full_message = header + length_bytes + \
            checksum_bytes + message_content.encode('utf-8')
        return full_message

    def parse_message(self, raw_data):
        # Parse the header
        header_data = raw_data[:47]  # Header size is 47 bytes
        header_info = Bob2Headers().parse_header(header_data)

        # Parse the rest of the message
        message_length = int.from_bytes(raw_data[47:52], byteorder='big')
        expected_checksum = struct.unpack('!I', raw_data[52:56])[0]
        message_content = raw_data[56:56 + message_length]
        actual_checksum = zlib.crc32(message_content)

        if expected_checksum != actual_checksum:
            raise ValueError("Checksum verification failed")

        # Add parsed message content to the header info
        header_info.update({
            "message_length": message_length,
            "checksum": expected_checksum,
            "message_content": message_content.decode('utf-8'),
        })

        return header_info
