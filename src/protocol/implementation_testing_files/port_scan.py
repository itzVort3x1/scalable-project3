import socket
import ipaddress
import subprocess
import concurrent.futures

# Define the network range to scan (e.g., '192.168.1.0/24')
network_range = '192.168.185.0/24'  # Modify this to your network's IP range
port_range = range(1, 22222)  # Ports to scan (1-1023 are common ports)

# Function to check if an IP is active
def ping_ip(ip):
    result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], stdout=subprocess.DEVNULL)
    return ip if result.returncode == 0 else None

# Function to scan ports on an active IP
def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((str(ip), port))
            return port
    except:
        return None

# Function to scan a single IP for open ports
def scan_ip(ip):
    open_ports = []
    for port in port_range:
        if scan_port(ip, port):
            open_ports.append(port)
    return (ip, open_ports) if open_ports else None

# Main function to scan the network for active IPs and open ports
def network_scan():
    active_ips = []
    open_ports_info = []

    # Step 1: Discover active IPs
    print(f"Scanning network for active IPs in range {network_range}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(ping_ip, ip) for ip in ipaddress.IPv4Network(network_range)]
        for future in concurrent.futures.as_completed(futures):
            ip = future.result()
            if ip:
                print(f"Active IP found: {ip}")
                active_ips.append(ip)

    # Step 2: Scan each active IP for open ports
    print("Scanning active IPs for open ports...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_ip, ip) for ip in active_ips]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                ip, open_ports = result
                print(f"Open ports on {ip}: {open_ports}")
                open_ports_info.append((ip, open_ports))

    return open_ports_info

# Run the network scan
if __name__ == "__main__":
    result = network_scan()
    print("\nNetwork scan complete.")
    for ip, ports in result:
        print(f"IP: {ip}, Open Ports: {ports}")
