import socket
import json

class PacketProcessing:
    def __init__(self):
        self.local_ip = self.get_local_ip()

    def get_local_ip(self):
        """Get the IP address of the current computer."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception as e:
            print(f"Error retrieving local IP: {e}")
            return None

    def process_packet(self, packet_json):
        """Process the JSON packet."""
        try:
            packet = json.loads(packet_json)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON: {e}")
            return

        dest_ip = packet.get("dest_ip")

        print(">>>>",self.local_ip)
        print("packet", packet_json)

        if not dest_ip:
            print("Packet is missing the destination IP.")
            return

        if dest_ip == self.local_ip:
            print("Packet is for this computer. Processing packet...")
            self.handle_packet(packet)
        else:
            print(f"Packet destined for {dest_ip}. Forwarding...")
            self.forward_packet(packet, dest_ip)

    def handle_packet(self, packet):
        """Handle packet intended for the local computer."""
        # Implement your logic for handling the packet
        print(f"Handling packet: {packet}")

    def forward_packet(self, packet, dest_ip):
        """Forward the packet to the correct destination."""
        packet["source_ip"] = self.local_ip
        updated_packet_json = json.dumps(packet)

        # Here we would forward the packet over the network.
        # For this example, we'll just print the action.
        print(f"Forwarding packet to {dest_ip}: {updated_packet_json}")