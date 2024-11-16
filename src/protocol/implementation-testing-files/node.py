import socket
import threading
import json

# Configuration
RECEIVE_PORT = 12345  # Port for receiving messages
SEND_PORT = 54321     # Port for sending messages

# Nodes in the network with static weights
adjacency_list = {
    "192.168.185.27": {"192.168.185.239": 1, "192.168.185.50": 8},
    "192.168.185.239": {"192.168.185.27": 3, "192.168.185.50": 2},
    "192.168.185.50": {"192.168.185.27": 8, "192.168.185.239": 3}
}

def get_local_ip():
    """Retrieve the local IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

def dijkstra(graph, start):
    """Compute shortest paths using Dijkstra's algorithm."""
    distances = {node: float('inf') for node in graph}  # Initialize distances
    distances[start] = 0  # Distance to self is 0
    visited = set()
    previous_nodes = {node: None for node in graph}  # Track the shortest path

    while len(visited) < len(graph):
        # Find the nearest unvisited node
        current_node = None
        current_min_distance = float('inf')
        for node, distance in distances.items():
            if node not in visited and distance < current_min_distance:
                current_node = node
                current_min_distance = distance

        if current_node is None:
            # All remaining nodes are unreachable
            break

        visited.add(current_node)

        # Update distances for neighbors
        for neighbor, weight in graph[current_node].items():
            if neighbor not in visited:
                new_distance = distances[current_node] + weight
                if new_distance < distances[neighbor]:
                    distances[neighbor] = new_distance
                    previous_nodes[neighbor] = current_node

    return distances, previous_nodes

def get_next_hop(previous_nodes, start, destination):
    """Trace back the shortest path to find the next hop."""
    current = destination
    while previous_nodes[current] != start:
        current = previous_nodes[current]
        if current is None:  # No valid path exists
            return None
    return current

def get_routing_table(local_ip):
    """Generate and display the routing table for the local node."""
    distances, _ = dijkstra(adjacency_list, local_ip)
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
            _, previous_nodes = dijkstra(adjacency_list, local_ip)
            next_hop = get_next_hop(previous_nodes, local_ip, dest_ip)
            if next_hop:
                print(f"Message hopping: {source_ip} -> {local_ip} -> {next_hop} -> {dest_ip}")
                forward_message(packet, next_hop)
            else:
                print(f"No route to {dest_ip}. Packet dropped.")
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
        _, previous_nodes = dijkstra(adjacency_list, local_ip)
        next_hop = get_next_hop(previous_nodes, local_ip, dest_ip)
        if next_hop:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((next_hop, RECEIVE_PORT))
                s.sendall(json.dumps(packet).encode())
                print(f"Message sent to {dest_ip} via {next_hop}: {message}")
        else:
            print(f"Message could not be delivered to {dest_ip}: No route found.")
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
