import socket
import threading
import json

# Configuration
RECEIVE_PORT = 5000  # Port for receiving messages
SEND_PORT = 5001     # Port for sending messages

# Sample routing table (Modify as needed)
routing_table = {
    "192.168.1.101": "192.168.1.102",  # Forward to 192.168.1.102 for 192.168.1.101
    "192.168.1.102": "192.168.1.103",  # Forward to 192.168.1.103 for 192.168.1.102
    "192.168.1.103": None              # Final destination
}

def get_local_ip():
    """Retrieve the local IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

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
            # Determine the next hop
            next_hop = routing_table.get(dest_ip)
            if next_hop:
                print(f"Forwarding message to {next_hop} for final destination {dest_ip}")
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
            s.connect((next_hop, SEND_PORT))
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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((dest_ip, RECEIVE_PORT))
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
        print("2. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            dest_ip = input("Enter the destination IP: ")
            message = input("Enter the message: ")
            send_message(local_ip, dest_ip, message)
        elif choice == "2":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")
