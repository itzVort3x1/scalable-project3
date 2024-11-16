import socket
import threading
import json

# Configuration
RECEIVE_PORT = 12345  # Port for receiving messages
SEND_PORT = 54321     # Port for sending messages

# Nodes in the network with static weights
adjacency_list = {
    "192.168.185.27": {"192.168.185.239": 1, "192.168.185.50": 8},
    "192.168.185.239": {"192.168.185.27": 2, "192.168.185.50": 2},
    "192.168.185.50": {"192.168.185.27": 8, "192.168.185.239": 3}
}

def get_local_ip():
    """Retrieve the local IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

def dijkstra(graph, start):
    """Compute shortest paths using Dijkstra's algorithm."""
    distances = {node: float('inf') for node in graph}
    distances[start] = 0
    visited = set()

    while visited != set(graph.keys()):
        # Find the unvisited node with the smallest distance
        current_node = min((node for node in distances if node not in visited), key=distances.get)
        visited.add(current_node)

        # Update distances to neighbors
        for neighbor, weight in graph[current_node].items():
            if neighbor not in visited:
                new_distance = distances[current_node] + weight
                if new_distance < distances[neighbor]:
                    distances[neighbor] = new_distance

    return distances

def get_routing_table(local_ip):
    """Generate and display the routing table for the local node."""
    distances = dijkstra(adjacency_list, local_ip)
    print("\nUpdated Routing Table:")
    for dest, cost in distances.items():
        if cost == float('inf'):
            print(f"Destination: {dest}, Cost: Unreachable")
        else:
            print(f"Destination: {dest}, Cost: {cost}")
    return distances

def handle_connection(conn, addr, local_ip):
    """Handle incoming messages and forward or process them."""
    try:
        data = conn.recv(1024).decode()
        if not data:
            return

        packet = json.loads(data)
        source_ip = packet["source_ip"]
        dest_ip = packet["dest_ip"]
        message = packet["message"]

        print(f"Received packet from {source_ip}: {packet}")

        # Check if this computer is the intended receiver
        if dest_ip == local_ip:
            print(f"Message delivered to this computer: {message}")
        else:
            # Determine the next hop using the routing table
            distances = dijkstra(adjacency_list, local_ip)
            next_hop = min(adjacency_list[local_ip], key=lambda neighbor: distances[neighbor])
            print(f"Message hopping: {source_ip} -> {local_ip} -> {next_hop} -> {dest_ip}")
            forward_message(packet, next_hop)
    except Exception as e:
        print(f"Error handling connection: {e}")
    finally:
        conn.close()

def forward_message(packet, next_hop):
    """Forward the message to the next hop."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((next_hop, RECEIVE_PORT))
            s.sendall(json.dumps(packet).encode())
            print(f"Packet forwarded to {next_hop}")
    except Exception as e:
        print(f"Error forwarding packet: {e}")

def start_receiver(local_ip):
    """Start the server to receive incoming messages."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((local_ip, RECEIVE_PORT))
        server_socket.listen(5)
        print(f"Receiver running on {local_ip}:{RECEIVE_PORT}")

        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_connection, args=(conn, addr, local_ip)).start()

def send_message(local_ip, dest_ip, message):
    """Send a message to the network."""
    packet = {
        "source_ip": local_ip,
        "dest_ip": dest_ip,
        "message": message
    }
    try:
        distances = dijkstra(adjacency_list, local_ip)
        next_hop = min(adjacency_list[local_ip], key=lambda neighbor: distances[neighbor])
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((next_hop, RECEIVE_PORT))
            s.sendall(json.dumps(packet).encode())
            print(f"Message sent to {dest_ip}: {message}")
    except Exception as e:
        print(f"Error sending message: {e}")

if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"Local IP: {local_ip}")

    # Start the receiver server in a separate thread
    threading.Thread(target=start_receiver, args=(local_ip,), daemon=True).start()

    # Interactive CLI
    while True:
        print("\nOptions:")
        print("1. Send a message")
        print("2. Show Routing Table")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            dest_ip = input("Enter the destination IP: ")
            message = input("Enter the message: ")
            send_message(local_ip, dest_ip, message)
        elif choice == "2":
            get_routing_table(local_ip)
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")
