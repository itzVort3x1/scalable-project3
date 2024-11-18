import os
import socket
import threading
import json
import zlib
import struct
import time
import queue
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import string
import random
from datetime import datetime



class Jarvis:
    def __init__(self, receive_port=12345, send_port=12345, adjacency_list_file="./protocol/discovery/adjacency_list.json"):
        self.receive_port = receive_port
        self.send_port = send_port
        self.local_ip = self.get_local_ip()
        self.adjacency_list = self.load_adjacency_list(adjacency_list_file)
        self.project_root = os.path.abspath(os.path.dirname(__file__))  # Get project root dynamically
        self.private_key_file = os.path.join(self.project_root, "private_key.pem")  # Private key path
        self.public_key_file = os.path.join(self.project_root, "public_key.pem")    # Public key path
        self.message_queue = queue.Queue()

    @staticmethod
    def get_local_ip():
        """Retrieve the local IP address."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]

    @staticmethod
    def load_adjacency_list(file_path):
        """Load the adjacency list from a JSON file."""
        try:
            with open(file_path, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return {}

    @staticmethod
    def dijkstra(graph, start):
        """Compute shortest paths using Dijkstra's algorithm."""
        distances = {node: float('inf') for node in graph}
        distances[start] = 0
        visited = set()
        previous_nodes = {node: None for node in graph}

        while len(visited) < len(graph):
            current_node = None
            current_min_distance = float('inf')
            for node, distance in distances.items():
                if node not in visited and distance < current_min_distance:
                    current_node = node
                    current_min_distance = distance

            if current_node is None:
                break

            visited.add(current_node)

            for neighbor, weight in graph[current_node].items():
                if neighbor not in visited:
                    new_distance = distances[current_node] + weight
                    if new_distance < distances[neighbor]:
                        distances[neighbor] = new_distance
                        previous_nodes[neighbor] = current_node

        return distances, previous_nodes

    @staticmethod
    def get_next_hop(previous_nodes, start, destination):
        """Trace back the shortest path to find the next hop."""
        current = destination
        while previous_nodes[current] != start:
            current = previous_nodes[current]
            if current is None:
                return None
        return current

    def decrypt_message(self, encrypted_message):
        """
        Decrypt a message using RSA private key.
        Args:
            encrypted_message (bytes): The encrypted message.
        Returns:
            str: The decrypted plain text message.
        """
        try:
            with open(self.private_key_file, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            # Decrypt the message using the private key
            decrypted = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"Decryption failed: {e}")
            raise

    def encrypt_message(self, message):
        """
        Encrypt a message using RSA public key.
        Args:
            message (str): The plain text message to encrypt.
        Returns:
            bytes: The encrypted message in bytes.
        """
        try:
            with open(self.public_key_file, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())

            # Encrypt the message using the public key
            encrypted = public_key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted
        except Exception as e:
            print(f"Encryption failed: {e}")
            raise

    def calculate_checksum(self, message_content):
        """Calculate CRC checksum for the message content."""
        return zlib.crc32(message_content.encode('utf-8'))

    def build_message(self, dest_ip, message, message_id, message_type="data"):
        """
        Build a structured message with RSA encryption, header, and checksum.
        Args:
            dest_ip (str): Destination IP address.
            message (str): Plain text message to send.
            message_id (str): Unique identifier for the message.
            message_type (str): Type of the message (default is 'data').
        Returns:
            bytes: The complete message with header and encrypted content.
        """
        try:
            print("\n--- Building the message ---")
            if isinstance(message, dict):
                message = json.dumps(message, separators=(',', ':'), ensure_ascii=False)
            print(f"Serialized JSON: {message}")

            # Encrypt the message
            encrypted_message = self.encrypt_message(message)
            print(f"Encrypted message: {encrypted_message}")

            # Calculate checksum directly on binary data
            checksum = zlib.crc32(encrypted_message)
            print(f"Checksum: {checksum}")

            checksum_bytes = struct.pack('!I', checksum)
            message_length = len(encrypted_message)
            length_bytes = message_length.to_bytes(5, byteorder='big')

            # Include message_id in the header
            header = json.dumps({
                "source_ip": self.local_ip,
                "dest_ip": dest_ip,
                "message_type": message_type,
                "message_id": message_id,  # Add message_id to the header
                "hop_count": 0
            }, separators=(',', ':')).encode('utf-8')

            # Combine all parts
            full_message = header + length_bytes + checksum_bytes + encrypted_message
            print(f"Full message bytes: {full_message}\n")

            return full_message
        except Exception as e:
            print(f"Error during message construction: {e}")
            raise ValueError("Failed to build the message.")

    def parse_message(self, raw_data):
        """
        Parse and validate a received message with RSA decryption.
        Args:
            raw_data (bytes): The raw message received.
        Returns:
            dict: The parsed message including the decrypted content.
        """
        try:
            print("\n--- Parsing the message ---")

            # Extract and decode the header
            header, header_length = self._extract_header(raw_data)
            print(f"Parsed header: {header}")

            # Extract message length and checksum
            message_length, expected_checksum = self._extract_length_and_checksum(raw_data, header_length)
            print(f"Message length from header: {message_length} bytes")
            print(f"Expected checksum (parse): {expected_checksum}")

            # Extract encrypted content
            encrypted_content = raw_data[header_length + 9:header_length + 9 + message_length]
            print(f"Encrypted content (parse): {encrypted_content}")

            # Handle special case for 'routing-info' message type
            if header.get("message_type") == "routing-info":
                return self._handle_routing_info(header, encrypted_content)

            # Perform checksum validation
            self._validate_checksum(encrypted_content, expected_checksum)

            # Decrypt the message content
            decrypted_message = self.decrypt_message(encrypted_content)
            print(f"Decrypted message: {decrypted_message}")

            # Parse JSON if applicable
            parsed_message = self._try_parse_json(decrypted_message)
            print(f"Parsed JSON message: {parsed_message}")

            # Attach decrypted message to the header
            header["message_content"] = parsed_message
            return header
        except Exception as e:
            print(f"Error during message parsing: {e}")
            raise

    # Helper Methods
    def _extract_header(self, raw_data):
        """Extract the header from the raw message."""
        header_length = raw_data.find(b'}') + 1
        if header_length == 0:
            raise ValueError("Header not properly formatted.")
        header = json.loads(raw_data[:header_length].decode('utf-8'))
        return header, header_length

    def _extract_length_and_checksum(self, raw_data, header_length):
        """Extract the message length and checksum."""
        message_length = int.from_bytes(raw_data[header_length:header_length + 5], byteorder='big')
        expected_checksum = struct.unpack('!I', raw_data[header_length + 5:header_length + 9])[0]
        return message_length, expected_checksum

    def _validate_checksum(self, encrypted_content, expected_checksum):
        """Validate the checksum of the encrypted content."""
        actual_checksum = zlib.crc32(encrypted_content)
        print(f"Actual checksum (parse): {actual_checksum}")
        if expected_checksum != actual_checksum:
            raise ValueError("Checksum verification failed.")

    def _handle_routing_info(self, header, encrypted_content):
        """Handle special case for 'routing-info' message type."""
        print("Message type is 'routing-info'. Skipping checksum validation.")
        decrypted_message = self.decrypt_message(encrypted_content)
        print(f"Decrypted message: {decrypted_message}")

        # Parse JSON if applicable
        try:
            parsed_message = json.loads(decrypted_message)
            self.store_adjacency_list(parsed_message)
            print(f"Parsed JSON message: {parsed_message}")
        except json.JSONDecodeError:
            print("Decrypted message is not valid JSON.")
            parsed_message = decrypted_message

        # Attach decrypted message to the header
        header["message_content"] = parsed_message
        return header

    def _try_parse_json(self, message):
        """Attempt to parse a message as JSON, if applicable."""
        try:
            return json.loads(message)
        except json.JSONDecodeError:
            print("Decrypted message is not valid JSON.")
            return message

    def handle_message(self, data):
        """
        Handle incoming messages.
        Args:
            data (bytes): Raw data received over the network.
        """
        try:
            # Parse the incoming message
            message = self.parse_message(data)
            print(f"Received message from {message['source_ip']}: {message['message_content']}")

            # Check if the message is an ACK
            if message["message_type"] == "ACK":
                # Process the acknowledgment
                self.process_ack(message)
                return

            # Increment hop_count for non-ACK messages
            message["hop_count"] += 1
            print(f"Incremented hop count: {message['hop_count']}")

            # Check if the message is for this node or needs to be forwarded
            if message["dest_ip"] == self.local_ip:
                print(f"Message delivered to this node: {message['message_content']}")

                print(">>>>>>>>>>>.",message['message_type'])

                if(message['message_type'] == 'data'):
                    # Send acknowledgment back to the source
                    ack_message = {
                        "message_type": "ACK",
                        "message_id": message["message_id"],  # Include the packet ID
                        "source_ip": self.local_ip,  # This node is the source for the ACK
                        "dest_ip": message["source_ip"],  # ACK goes back to the original sender
                        "hop_count": 0  # Reset hop count for ACK
                    }
                    print(f"Sending ACK for message ID {message['message_id']} to {message['source_ip']}")
                    self.send_message(message["source_ip"], ack_message)
                else:
                    print("Message delivered to this node: ", message['message_content'])
            else:
                # Forward the message to the next hop
                _, previous_nodes = self.dijkstra(self.adjacency_list, self.local_ip)
                next_hop = self.get_next_hop(previous_nodes, self.local_ip, message["dest_ip"])
                if next_hop:
                    print(f"Message hopping: {message['source_ip']} -> {self.local_ip} -> {next_hop} -> {message['dest_ip']}")
                    self.forward_message(message, next_hop)
                else:
                    print(f"No route to {message['dest_ip']}. Packet dropped.")
        except ValueError as e:
            print(f"Error handling message: {e}")

    def process_ack(self, ack_message):
        """
        Process an acknowledgment message.
        Args:
            ack_message (dict): The acknowledgment message.
        """
        try:
            acked_message_id = ack_message["message_id"]
            print(f"Processing ACK for message ID: {acked_message_id}")

            # Iterate through the queue to find and remove the corresponding message
            queue_size = self.message_queue.qsize()
            temp_queue = []

            for _ in range(queue_size):
                queued_item = self.message_queue.get()
                if queued_item["message_id"] == acked_message_id:
                    print(f"Message ID {acked_message_id} acknowledged and removed from queue.")
                    continue  # Skip re-adding this item
                temp_queue.append(queued_item)

            # Re-add remaining items to the queue
            for item in temp_queue:
                self.message_queue.put(item)

        except KeyError:
            print(f"Invalid ACK message: {ack_message}")


    def forward_message(self, message, next_hop):
        """Forward the message to the next hop."""
        print("Forwarding message...")
        time.sleep(2)  # Simulate processing delay

        # Rebuild the message with the updated hop_count
        full_message = self.build_message(message["dest_ip"], message["message_content"], message["message_id"])
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((next_hop, self.send_port))
                s.sendall(full_message)
                print(f"Packet forwarded to {next_hop}")
        except Exception as e:
            print(f"Error forwarding packet: {e}")

    def send_message(self, dest_ip, message):
        """Send a structured message to the network."""
        print("Preparing to send message...")
        time.sleep(2)  # Simulate processing delay

        message_id = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        timestamp = datetime.now().isoformat()  # ISO 8601 format timestamp
        self.message_queue.put({
            "message_id": message_id,
            "dest_ip": dest_ip,
            "message": message,
            "timestamp": timestamp  # Add timestamp
        })

        full_message = self.build_message(dest_ip, message, message_id)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((dest_ip, self.send_port))
                s.sendall(full_message)
                print(f"Message sent to {dest_ip}: {message}")
        except Exception as e:
            print(f"Error sending message: {e}")

    def store_adjacency_list(self, adjacency_list):
        """Store the adjacency list locally."""
        self.adjacency_list = adjacency_list  # Update the in-memory adjacency list
        with open("./discovery/adjacency_list.json", "w") as file:
            json.dump(adjacency_list, file, indent=4)
        print("Adjacency list stored successfully.")


    def start_receiver(self):
        """Start the server to receive direct messages."""
        print("Starting receiver server...")
        time.sleep(2)  # Simulate processing delay

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.local_ip, self.receive_port))
            server_socket.listen(5)
            print(f"Receiver running on {self.local_ip}:{self.receive_port}")

            while True:
                conn, _ = server_socket.accept()
                with conn:
                    data = conn.recv(4096)
                    print(">>>>>", data)
                    self.handle_message(data)

    def start(self):
        """Start the receiver server in a separate thread."""
        threading.Thread(target=self.start_receiver, daemon=True).start()

        # Interactive CLI
        while True:
            print("\nOptions:")
            print("1. Send a message")
            print("2. Exit")
            choice = input("Enter your choice: ")

            if choice == "1":
                dest_ip = input("Enter the destination IP: ")
                message = input("Enter the message: ")
                self.send_message(dest_ip, message)
            elif choice == "2":
                print("Exiting...")
                break
            else:
                print("Invalid choice.")


if __name__ == "__main__":
    node = Jarvis()
    print(f"Local IP: {node.local_ip}")
    node.start()
