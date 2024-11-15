import argparse
from protocol.bob2_protocol import Bob2Protocol

def main():
    parser = argparse.ArgumentParser(
        description="Bob2 Protocol Message Builder and Parser"
    )

    parser.add_argument('--version_major', type=int,
                        required=True, help='Protocol version major')
    parser.add_argument('--version_minor', type=int,
                        required=True, help='Protocol version minor')
    parser.add_argument('--message_type', type=int, required=True,
                        help='Message type (e.g., data, control, etc.)')
    parser.add_argument('--dest_ip', type=str,
                        required=True, help='Destination IPv6 address')
    parser.add_argument('--dest_port', type=int,
                        required=True, help='Destination port number')
    parser.add_argument('--source_ip', type=str,
                        required=True, help='Source IPv6 address')
    parser.add_argument('--source_port', type=int,
                        required=True, help='Source port number')
    parser.add_argument('--sequence_number', type=int,
                        required=True, help='Sequence number for the message')
    parser.add_argument('--message_content', type=str,
                        required=True, help='Content of the message')
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=12345, help="Server port")
    parser.add_argument("--mode", choices=["client", "server"], required=True,
                        help="Start as client or server")

    args = parser.parse_args()

    # Initialize the Bob2Protocol instance
    bob2 = Bob2Protocol(
        version_major=args.version_major,
        version_minor=args.version_minor,
        host=args.host,
        port=args.port,
        dest_ip=args.dest_ip,
        dest_port=args.dest_port,
        source_ip=args.source_ip,
        source_port=args.source_port,
        mode=args.mode
    )

    # Start either as client or server
    if args.mode == "client":
        bob2.connect_to_server()
    elif args.mode == "server":
        bob2.start_server()

if __name__ == "__main__":
    main()
