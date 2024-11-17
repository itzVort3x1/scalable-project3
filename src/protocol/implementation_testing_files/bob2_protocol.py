import struct
import socket
import logging
import time
import json
import select
import sys
import zlib
import threading
from protocol.handshake import Handshake
from protocol.Packet_processing import PacketProcessing

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Bob2Protocol:
    def __init__(self, version_major=0, version_minor=0, host="0.0.0.0", port=12345, mode="", dest_ip="127.0.0.1", dest_port=12345, source_ip="127.0.0.1", source_port=12345):
        self.version_major = version_major
        self.version_minor = version_minor
        self.server_host = host  # Bind to all interfaces
        self.server_port = port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.source_ip = dest_port
        self.source_port = source_port
        self.role = mode  # Add role to indicate "client" or "server"
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.handshake = Handshake()
        self.connection = None  # To hold the active connection

    def start_server(self):
        self.server_socket.bind((self.server_host, self.server_port))
        self.server_socket.listen(1)
        logging.info(f"Server listening on {self.server_host}:{self.server_port}")
        
        self.connection, addr = self.server_socket.accept()
        logging.info(f"Server connected to {addr}")
        
        self.perform_handshake(client_socket=self.connection, is_server=True)
        self.start_threads(self.connection)

    def connect_to_server(self):
        self.client_socket.connect((self.server_host, self.server_port))
        logging.info(f"Connected to server at {self.server_host}:{self.server_port}")
        self.perform_handshake(client_socket=self.client_socket, is_server=False)
        self.start_threads(self.client_socket)

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
            print("forwarding message")
            print("message_dict", message_dict)
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
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                PacketProcessing().process_packet(decrypted_message)
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                message_dict = json.loads(decrypted_message)
                logging.info(f"Message received by {self.role}: {message_dict}")
                return message_dict
            else:
                logging.warning("No message received or connection closed.")
                return None
        except Exception as e:
            logging.error(f"Failed to receive message: {e}")
            return None

    def start_threads(self, client_socket):
        # Threads for sending and receiving messages
        receive_thread = threading.Thread(target=self.receive_messages_thread, args=(client_socket,))
        send_thread = threading.Thread(target=self.send_messages_thread, args=(client_socket,))
        receive_thread.start()
        send_thread.start()
        
        receive_thread.join()
        send_thread.join()
        client_socket.close()

    def receive_messages_thread(self, client_socket):
        while True:
            message = self.receive_message(client_socket)
            if message:
                logging.info(f"Message from {'server' if self.role == 'client' else 'client'}: {message}")
            else:
                logging.info("Connection closed by the other party.")
                break

    def forward_packet(self, packet, dest_ip):
        """Forward the packet to the correct destination."""
        print(">>>>>>>>>>>>> forwarding packet", packet)
        print(">>>>>>>>>>>>> forwarding dest_ip", dest_ip)
        self.send_message(self.client_socket, packet)


    def send_messages_thread(self, client_socket):
        while True:
            message_content = input("Enter message to send (or 'exit' to quit): ")
            if message_content.lower() == "exit":
                logging.info("Exiting communication.")
                client_socket.close()
                break

            message_dict = {
                'version_major': self.version_major,
                'version_minor': self.version_minor,
                'message_type': 0,
                'dest_ip': self.dest_ip,
                'dest_port': self.dest_port,
                'source_ip': self.source_ip,
                'source_port': self.source_port,
                'sequence_number': 1,
                'timestamp': int(time.time()),
                'message_length': len(message_content),
                'checksum': zlib.crc32(message_content.encode('utf-8')),
                'message_content': message_content
            }
            self.send_message(client_socket, message_dict)
