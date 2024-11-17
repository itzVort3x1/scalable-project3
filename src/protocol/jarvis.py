import socket
import threading
import json
import zlib
import struct
import time


class Jarvis:
    def __init__(self, receive_port=12345, send_port=12345, adjacency_list_file="./protocol/discovery/adjacency_list.json"):
        self.receive_port = receive_port
        self.send_port = send_port
        self.local_ip = self.get_local_ip()
        self.adjacency_list = self.load_adjacency_list(adjacency_list_file)
        self.encryption_key = 3

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
        """Decrypt a message using a simple Caesar cipher."""
        decrypted = ''.join(chr((ord(char) - self.encryption_key) % 256) for char in encrypted_message)
        return decrypted

    def encrypt_message(self, message):
        """Encrypt a message using a simple Caesar cipher."""
        encrypted = ''.join(chr((ord(char) + self.encryption_key) % 256) for char in message)
        return encrypted

    def calculate_checksum(self, message_content):
        """Calculate CRC checksum for the message content."""
        return zlib.crc32(message_content.encode('utf-8'))

    def build_message(self, dest_ip, message):
        """Build a structured message with header, length, and checksum."""
        print("Building the message...")
        time.sleep(2)  # Simulate processing delay

        message_content = self.encrypt_message(message)
        print(f"Encrypted message content: {message_content}")

        checksum = self.calculate_checksum(message_content)
        print(f"Calculated checksum: {checksum}")

        checksum_bytes = struct.pack('!I', checksum)

        message_length = len(message_content)
        print(f"Message length: {message_length} bytes")

        length_bytes = message_length.to_bytes(5, byteorder='big')

        header = json.dumps({
            "source_ip": self.local_ip,
            "dest_ip": dest_ip,
        }).encode('utf-8')

        full_message = header + length_bytes + checksum_bytes + message_content.encode('utf-8')
        print(f"Full message: {full_message}")

        return full_message

    def parse_message(self, raw_data):
        """Parse and validate a received message."""
        print("Parsing the message...")
        time.sleep(2)  # Simulate processing delay

        header_length = raw_data.find(b'}') + 1
        header = json.loads(raw_data[:header_length].decode('utf-8'))
        print(f"Parsed header: {header}")

        message_length = int.from_bytes(raw_data[header_length:header_length + 5], byteorder='big')
        print(f"Message length from header: {message_length} bytes")

        expected_checksum = struct.unpack('!I', raw_data[header_length + 5:header_length + 9])[0]
        print(f"Expected checksum: {expected_checksum}")

        message_content = raw_data[header_length + 9:header_length + 9 + message_length].decode('utf-8')
        actual_checksum = zlib.crc32(message_content.encode('utf-8'))

        if expected_checksum != actual_checksum:
            raise ValueError("Checksum verification failed")

        decrypted_message = self.decrypt_message(message_content)
        print(f"Decrypted message content: {decrypted_message}")

        header["message_content"] = decrypted_message
        return header

    def handle_message(self, data):
        """Handle incoming messages."""
        try:
            message = self.parse_message(data)
            print(f"Received message from {message['source_ip']}: {message['message_content']}")
        except ValueError as e:
            print(f"Error handling message: {e}")

    def send_message(self, dest_ip, message):
        """Send a structured message to the network."""
        print("Preparing to send message...")
        time.sleep(2)  # Simulate processing delay

        full_message = self.build_message(dest_ip, message)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((dest_ip, self.send_port))
                s.sendall(full_message)
                print(f"Message sent to {dest_ip}: {message}")
        except Exception as e:
            print(f"Error sending message: {e}")

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
                    print(f"Raw data received: {data}")
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
