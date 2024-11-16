import socket
import threading
import json
import logging
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

logging.basicConfig(level=logging.INFO)


class Handshake:
    """Implements key generation and shared key establishment using Diffie-Hellman."""

    def __init__(self):
        self.shared_key = None

    def generate_keys(self):
        """Generate private and public keys for Diffie-Hellman."""
        private_key = os.urandom(16)  # Random 16-byte private key
        public_key = int.from_bytes(private_key, byteorder='big') ** 2  # Simplified DH-like public key
        return private_key, public_key

    def establish_shared_key(self, peer_public_key, private_key):
        """Derive a shared secret (simplified for demonstration)."""
        self.shared_key = (int(peer_public_key) ** int.from_bytes(private_key, byteorder='big')) % 23  # Simplified
        logging.info(f"Shared key established: {self.shared_key}")


class Jarvis:
    def __init__(self, receive_port=12345, send_port=54321, adjacency_list=None):
        self.receive_port = receive_port
        self.send_port = send_port
        self.adjacency_list = adjacency_list or {}
        self.local_ip = self.get_local_ip()
        self.handshake = Handshake()
        logging.info(f"Jarvis initialized on IP: {self.local_ip}")

    @staticmethod
    def get_local_ip():
        """Retrieve the local IP address."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]

    def perform_handshake(self, client_socket, is_server):
        """Perform a handshake to establish a shared secret key."""
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

    def encrypt_message(self, message):
        """Encrypt a message using the shared key."""
        if not self.handshake.shared_key:
            raise ValueError("Shared key not established.")
        key = self.handshake.shared_key.to_bytes(16, byteorder='big')
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = iv + encryptor.update(message.encode()) + encryptor.finalize()
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        """Decrypt a message using the shared key."""
        if not self.handshake.shared_key:
            raise ValueError("Shared key not established.")
        key = self.handshake.shared_key.to_bytes(16, byteorder='big')
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def send_message(self, dest_ip, message):
        """Send a message to the network."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((dest_ip, self.send_port))
                # Perform handshake
                self.perform_handshake(s, is_server=False)

                # Encrypt message before sending
                encrypted_message = self.encrypt_message(message)
                packet = {
                    "source_ip": self.local_ip,
                    "dest_ip": dest_ip,
                    "message": encrypted_message.hex(),
                }
                s.sendall(json.dumps(packet).encode())
                logging.info(f"Encrypted message sent to {dest_ip}.")
        except Exception as e:
            logging.error(f"Error sending message: {e}")

    def handle_message(self, data, conn):
        """Handle incoming messages."""
        try:
            packet = json.loads(data)
            source_ip = packet["source_ip"]
            dest_ip = packet["dest_ip"]
            encrypted_message = bytes.fromhex(packet["message"])

            # Decrypt the received message
            decrypted_message = self.decrypt_message(encrypted_message).decode()
            if dest_ip == self.local_ip:
                logging.info(f"Decrypted message delivered: {decrypted_message}")
            else:
                logging.warning(f"Message not intended for this IP: {dest_ip}")
        except Exception as e:
            logging.error(f"Error handling message: {e}")

    def start_receiver(self):
        """Start the server to receive direct messages."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.local_ip, self.receive_port))
            server_socket.listen(5)
            logging.info(f"Receiver running on {self.local_ip}:{self.receive_port}")

            while True:
                conn, _ = server_socket.accept()
                with conn:
                    # Perform handshake
                    self.perform_handshake(conn, is_server=True)
                    data = conn.recv(1024).decode()
                    self.handle_message(data, conn)

    def run(self):
        """Run Jarvis."""
        threading.Thread(target=self.start_receiver, daemon=True).start()
        while True:
            dest_ip = input("Enter destination IP: ")
            message = input("Enter message: ")
            self.send_message(dest_ip, message)


if __name__ == "__main__":
    jarvis = Jarvis()
    jarvis.run()
