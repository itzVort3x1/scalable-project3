import socket

def get_ip_address():
    try:
        # Create a socket and connect to a public DNS server
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        return f"Error retrieving IP: {e}"

ip_address = get_ip_address()
print(f"IP Address: {ip_address}")
