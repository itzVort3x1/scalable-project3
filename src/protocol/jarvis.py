import socket
import threading
import json
import requests
from cryptography.fernet import Fernet
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl


class Jarvis:
    def __init__(self, receive_port=12345, send_port=54321, key_server_port=4443, adjacency_list_file="./discovery/adjacency_list.json"):
        self.receive_port = receive_port
        self.send_port = send_port
        self.key_server_port = key_server_port
        self.local_ip = self.get_local_ip()
        self.adjacency_list = self.load_adjacency_list(adjacency_list_file)

        # Load or fetch the encryption key
        self.encryption_key = self.load_or_fetch_shared_key()
        self.cipher = Fernet(self.encryption_key)

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

    def load_or_fetch_shared_key(self):
        """Load the shared encryption key from a file or fetch it from a key server."""
        key_file = "shared_key.key"
        try:
            with open(key_file, "rb") as file:
                print(f"Loaded shared key from {key_file}")
                return file.read()
        except FileNotFoundError:
            # Fetch the key from the key server
            key_server_url = f"https://{self.get_key_server_ip()}:{self.key_server_port}/shared_key.key"
            try:
                response = requests.get(key_server_url, verify=False)  # Disable SSL verification for simplicity
                response.raise_for_status()
                with open(key_file, "wb") as file:
                    file.write(response.content)
                print(f"Fetched shared key from {key_server_url} and saved to {key_file}")
                return response.content
            except Exception as e:
                print(f"Failed to fetch shared key: {e}")
                raise e

    def get_key_server_ip(self):
        """Determine the IP address of the key server (first node in the adjacency list)."""
        if self.adjacency_list:
            return list(self.adjacency_list.keys())[0]  # Assume the first node is the key server
        raise ValueError("No key server IP available in adjacency list.")

    def start_key_server(self):
        """Start an HTTPS server to distribute the shared key."""
        key_file = "shared_key.key"
        if not hasattr(self, "encryption_key"):
            print("Shared key not generated. Cannot start key server.")
            return

        # Save the key locally if it doesn't exist
        with open(key_file, "wb") as file:
            file.write(self.encryption_key)

        class KeyRequestHandler(SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                return  # Suppress HTTP request logging

        httpd = HTTPServer((self.local_ip, self.key_server_port), KeyRequestHandler)
        httpd.socket = ssl.wrap_socket(httpd.socket, certfile="cert.pem", keyfile="key.pem", server_side=True)
        print(f"Key server running on https://{self.local_ip}:{self.key_server_port}")
        httpd.serve_forever()

    def encrypt_message(self, message):
        """Encrypt a message."""
        return self.cipher.encrypt(message.encode()).decode()

    def decrypt_message(self, encrypted_message):
        """Decrypt a message."""
        return self.cipher.decrypt(encrypted_message.encode()).decode()

    def handle_message(self, data):
        """Handle incoming messages, decrypt, and process or forward them."""
        try:
            packet = json.loads(data)
            source_ip = packet["source_ip"]
            dest_ip = packet["dest_ip"]
            encrypted_message = packet["message"]

            # Decrypt the message
            message = self.decrypt_message(encrypted_message)
            print(f"Received packet from {source_ip}: {packet}")

            if dest_ip == self.local_ip:
                print(f"Message delivered to this computer: {message}")
            else:
                _, previous_nodes = self.dijkstra(self.adjacency_list, self.local_ip)
                next_hop = self.get_next_hop(previous_nodes, self.local_ip, dest_ip)
                if next_hop:
                    print(f"Message hopping: {source_ip} -> {self.local_ip} -> {next_hop} -> {dest_ip}")
                    self.forward_message(packet, next_hop)
                else:
                    print(f"No route to {dest_ip}. Packet dropped.")
        except Exception as e:
            print(f"Error handling message: {e}")

    def send_message(self, dest_ip, message):
        """Send a message to the network."""
        encrypted_message = self.encrypt_message(message)
        packet = {
            "source_ip": self.local_ip,
            "dest_ip": dest_ip,
            "message": encrypted_message
        }
        try:
            _, previous_nodes = self.dijkstra(self.adjacency_list, self.local_ip)
            next_hop = self.get_next_hop(previous_nodes, self.local_ip, dest_ip)
            if next_hop:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((next_hop, self.send_port))
                    s.sendall(json.dumps(packet).encode())
                    print(f"Message sent to {dest_ip} via {next_hop}: {message}")
            else:
                print(f"Message could not be delivered to {dest_ip}: No route found.")
        except Exception as e:
            print(f"Error sending message: {e}")

    def start(self):
        """Start the receiver and optionally the key server."""
        threading.Thread(target=self.start_receiver, daemon=True).start()

        if self.local_ip == self.get_key_server_ip():
            threading.Thread(target=self.start_key_server, daemon=True).start()

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


if __name__ == "__main__":
    node = Jarvis()
    print(f"Local IP: {node.local_ip}")
    node.start()
