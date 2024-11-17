import socket
import threading
import json
from protocol.handshake import Handshake


class Jarvis:
    def __init__(self, receive_port=12345, send_port=54321, adjacency_list_file="./discovery/adjacency_list.json"):
        self.RECEIVE_PORT = receive_port
        self.SEND_PORT = send_port
        self.local_ip = self.get_local_ip()
        self.adjacency_list = self.load_adjacency_list(adjacency_list_file)
        self.handshake = Handshake()

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

    def get_next_hop(self, previous_nodes, start, destination):
        """Trace back the shortest path to find the next hop."""
        current = destination
        while previous_nodes[current] != start:
            current = previous_nodes[current]
            if current is None:
                return None
        return current

    def handle_message(self, data):
        """Handle incoming messages and forward or process them."""
        try:
            packet = json.loads(data)
            source_ip = packet["source_ip"]
            dest_ip = packet["dest_ip"]
            message = packet["message"]

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

    def start_receiver(self):
        """Start the server to receive direct messages."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.local_ip, self.RECEIVE_PORT))
            server_socket.listen(5)
            print(f"Receiver running on {self.local_ip}:{self.RECEIVE_PORT}")

            while True:
                conn, _ = server_socket.accept()
                with conn:
                    data = conn.recv(1024).decode()
                    self.handle_message(data)

    def start_sending_server(self):
        """Start the server to handle forwarded messages."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.local_ip, self.SEND_PORT))
            server_socket.listen(5)
            print(f"Sender running on {self.local_ip}:{self.SEND_PORT}")

            while True:
                conn, _ = server_socket.accept()
                with conn:
                    data = conn.recv(1024).decode()
                    self.handle_message(data)

    def send_message(self, dest_ip, message):
        """Send a message to the network."""
        packet = {
            "source_ip": self.local_ip,
            "dest_ip": dest_ip,
            "message": message
        }
        try:
            _, previous_nodes = self.dijkstra(self.adjacency_list, self.local_ip)
            next_hop = self.get_next_hop(previous_nodes, self.local_ip, dest_ip)
            if next_hop:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((next_hop, self.SEND_PORT))
                    packet['message'] = self.handshake.encrypt_message(message)
                    s.sendall(json.dumps(packet).encode())
                    print(f"Message sent to {dest_ip} via {next_hop}: {message}")
            else:
                print(f"Message could not be delivered to {dest_ip}: No route found.")
        except Exception as e:
            print(f"Error sending message: {e}")

    def forward_message(self, packet, next_hop):
        """Forward the message to the next hop."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((next_hop, self.SEND_PORT))
                s.sendall(json.dumps(packet).encode())
                print(f"Packet forwarded to {next_hop}")
        except Exception as e:
            print(f"Error forwarding packet: {e}")

    def start(self):
        """Start the receiver and sender servers in separate threads."""
        threading.Thread(target=self.start_receiver, daemon=True).start()
        threading.Thread(target=self.start_sending_server, daemon=True).start()

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
    jarvis = Jarvis()
    print(f"Local IP: {jarvis.local_ip}")
    jarvis.start()
