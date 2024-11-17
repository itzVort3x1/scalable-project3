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

    # def build_message(self, dest_ip, message, message_type="data"):
    #     """Build a structured message with header, length, and checksum."""
    #     try:
    #         print("Building the message...")

    #         # Encrypt the message content
    #         message_content = self.encrypt_message(message)
    #         print(f"Encrypted message content: {message_content}")

    #         # Calculate checksum
    #         checksum = self.calculate_checksum(message_content)
    #         print(f"Calculated checksum (build): {checksum}")

    #         # Pack checksum into 4 bytes
    #         checksum_bytes = struct.pack('!I', checksum)

    #         # Determine message length
    #         message_length = len(message_content.encode('latin1'))  # Use latin1 to ensure consistent byte length
    #         print(f"Message length: {message_length} bytes")

    #         # Pack message length into 5 bytes
    #         length_bytes = message_length.to_bytes(5, byteorder='big')

    #         # Create the header with JSON and encode it as UTF-8
    #         header = json.dumps({
    #             "source_ip": self.local_ip,
    #             "dest_ip": dest_ip,
    #             "message_type": message_type,
    #             "hop_count": 0  # Initial hop count is 0
    #         }).encode('utf-8')

    #         # Concatenate all parts to form the full message
    #         full_message = header + length_bytes + checksum_bytes + message_content.encode('latin1')
    #         print(f"Full message constructed: {full_message}")

    #         return full_message

    #     except Exception as e:
    #         print(f"Error building message: {e}")
    #         raise ValueError("Failed to build the message.")

    def build_message(self, dest_ip, message, message_type="data"):
        """Build a structured message with header, length, and checksum."""
        try:
            print("\n--- Building the message ---")

            # Serialize JSON consistently if the message is a dictionary
            if isinstance(message, dict):
                message = json.dumps(message, separators=(',', ':'), ensure_ascii=False)
            print(f"Serialized JSON: {message}")

            # Encrypt the message content
            message_content = self.encrypt_message(message)
            print(f"Encrypted content: {message_content}")

            # Calculate checksum
            checksum = self.calculate_checksum(message_content)
            print(f"Checksum (build): {checksum}")

            # Pack checksum into 4 bytes
            checksum_bytes = struct.pack('!I', checksum)

            # Determine message length
            message_length = len(message_content.encode('latin1'))
            print(f"Message length (bytes): {message_length}")

            # Pack message length into 5 bytes
            length_bytes = message_length.to_bytes(5, byteorder='big')

            # Create header JSON and encode it as UTF-8
            header = json.dumps({
                "source_ip": self.local_ip,
                "dest_ip": dest_ip,
                "message_type": message_type,
                "hop_count": 0
            }, separators=(',', ':')).encode('utf-8')

            # Concatenate all parts to form the full message
            full_message = header + length_bytes + checksum_bytes + message_content.encode('latin1')
            print(f"Full message bytes: {full_message}\n")

            return full_message

        except Exception as e:
            print(f"Error during message construction: {e}")
            raise ValueError("Failed to build the message.")


    # def parse_message(self, raw_data):
    #     """Parse and validate a received message."""
    #     try:
    #         print("Parsing the message...")

    #         # Extract and decode the header
    #         header_length = raw_data.find(b'}') + 1
    #         if header_length == 0:
    #             raise ValueError("Header not properly formatted.")
            
    #         header = json.loads(raw_data[:header_length].decode('utf-8'))
    #         print(f"Parsed header: {header}")

    #         # Extract message length
    #         message_length = int.from_bytes(raw_data[header_length:header_length + 5], byteorder='big')
    #         print(f"Message length from header: {message_length} bytes")

    #         # Ensure raw_data is long enough
    #         if len(raw_data) < header_length + 9 + message_length:
    #             raise ValueError("Incomplete raw data received.")

    #         # Extract checksum
    #         expected_checksum = struct.unpack('!I', raw_data[header_length + 5:header_length + 9])[0]
    #         print(f"Expected checksum (parse): {expected_checksum}")

    #         # Extract and decode message content
    #         encrypted_content = raw_data[header_length + 9:header_length + 9 + message_length].decode('latin1')
    #         print(f"Encrypted content (parse): {encrypted_content}")

    #         # Recalculate checksum
    #         actual_checksum = zlib.crc32(encrypted_content.encode('latin1'))
    #         print(f"Actual checksum (parse): {actual_checksum}")

    #         if expected_checksum != actual_checksum:
    #             raise ValueError("Checksum verification failed.")

    #         # Decrypt the message content
    #         decrypted_message = self.decrypt_message(encrypted_content)
    #         print(f"Decrypted message content: {decrypted_message}")

    #         # Attach the decrypted message to the header
    #         header["message_content"] = decrypted_message
    #         return header

    #     except json.JSONDecodeError as e:
    #         print(f"Error decoding header: {e}")
    #         raise ValueError("Invalid JSON in header.")
    #     except UnicodeDecodeError as e:
    #         print(f"Error decoding message content: {e}")
    #         raise ValueError("Message content is not valid UTF-8.")
    #     except Exception as e:
    #         print(f"Unexpected error while parsing message: {e}")
    #         raise

    def parse_message(self, raw_data):
        """Parse and validate a received message."""
        try:
            print("\n--- Parsing the message ---")

            # Extract and decode the header
            header_length = raw_data.find(b'}') + 1
            if header_length == 0:
                raise ValueError("Header not properly formatted.")
            
            header = json.loads(raw_data[:header_length].decode('utf-8'))
            print(f"Parsed header: {header}")

            # Extract message length
            message_length = int.from_bytes(raw_data[header_length:header_length + 5], byteorder='big')
            print(f"Message length from header: {message_length} bytes")

            # Extract checksum
            expected_checksum = struct.unpack('!I', raw_data[header_length + 5:header_length + 9])[0]
            print(f"Expected checksum (parse): {expected_checksum}")

            # Extract encrypted content
            encrypted_content = raw_data[header_length + 9:header_length + 9 + message_length].decode('latin1')
            print(f"Encrypted content (parse): {encrypted_content}")

            # If message_type is 'routing-info', skip checksum validation
            if header.get("message_type") == "routing-info":
                print("Message type is 'routing-info'. Skipping checksum validation.")
                decrypted_message = self.decrypt_message(encrypted_content)
                print(f"Decrypted message: {decrypted_message}")

                # Parse JSON if applicable
                try:
                    decrypted_message = json.loads(decrypted_message)
                    self.store_adjacency_list(decrypted_message)
                    print(f"Parsed JSON message: {decrypted_message}")
                except json.JSONDecodeError:
                    print("Decrypted message is not valid JSON.")

                # Attach decrypted message to the header and return
                header["message_content"] = decrypted_message
                return header

            # Otherwise, perform checksum validation
            actual_checksum = zlib.crc32(encrypted_content.encode('latin1'))
            print(f"Actual checksum (parse): {actual_checksum}")

            if expected_checksum != actual_checksum:
                raise ValueError("Checksum verification failed.")

            # Decrypt the message content
            decrypted_message = self.decrypt_message(encrypted_content)
            print(f"Decrypted message: {decrypted_message}")

            # Parse JSON if applicable
            try:
                decrypted_message = json.loads(decrypted_message)
                print(f"Parsed JSON message: {decrypted_message}")
            except json.JSONDecodeError:
                print("Decrypted message is not valid JSON.")

            # Attach decrypted message to the header
            header["message_content"] = decrypted_message
            return header

        except Exception as e:
            print(f"Error during message parsing: {e}")
            raise



    def handle_message(self, data):
        """Handle incoming messages."""
        try:
            message = self.parse_message(data)
            print(f"Received message from {message['source_ip']}: {message['message_content']}")

            # Increment hop_count
            message["hop_count"] += 1
            print(f"Incremented hop count: {message['hop_count']}")

            # Check if the message is for this node or needs to be forwarded
            if message["dest_ip"] == self.local_ip:
                print(f"Message delivered to this node: {message['message_content']}")
            else:
                _, previous_nodes = self.dijkstra(self.adjacency_list, self.local_ip)
                next_hop = self.get_next_hop(previous_nodes, self.local_ip, message["dest_ip"])
                if next_hop:
                    print(f"Message hopping: {message['source_ip']} -> {self.local_ip} -> {next_hop} -> {message['dest_ip']}")
                    self.forward_message(message, next_hop)
                else:
                    print(f"No route to {message['dest_ip']}. Packet dropped.")
        except ValueError as e:
            print(f"Error handling message: {e}")

    def forward_message(self, message, next_hop):
        """Forward the message to the next hop."""
        print("Forwarding message...")
        time.sleep(2)  # Simulate processing delay

        # Rebuild the message with the updated hop_count
        full_message = self.build_message(message["dest_ip"], message["message_content"])
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

        full_message = self.build_message(dest_ip, message)
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
        with open("./protocol/discovery/adjacency_list.json", "w") as file:
            json.dump(adjacency_list, file, indent=4)
        print("Adjacency list stored successfully.")

    # def start_receiver(self):
    #     """Start the server to receive direct messages."""
    #     print("Starting receiver server...")
    #     time.sleep(2)  # Simulate processing delay

    #     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    #         server_socket.bind((self.local_ip, self.receive_port))
    #         server_socket.listen(5)
    #         print(f"Receiver running on {self.local_ip}:{self.receive_port}")

    #         while True:
    #             conn, _ = server_socket.accept()
    #             with conn:
    #                 raw_data = conn.recv(4096)

    #                 # Process the data as bytes (without decode)
    #                 data_bytes = raw_data

    #                 # Process the data as a string (with decode)
    #                 data_string = raw_data.decode()
    #                 print(data_string)

    #             try:
    #                 if data_string['message_type'] == 'routing-info':
    #                     self.store_adjacency_list(data_string['message'])
    #                 else:
    #                     self.handle_message(data_bytes)
    #             except Exception as e:
    #                 print(f"Error handling message: {e}")

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
                    data = conn.recv(8192)
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
