import unittest
import ipaddress
import argparse
import sys
from protocol.bob2_protocol import Bob2Protocol
from protocol.necessary_headers import Bob2Headers


def get_args():
    parser = argparse.ArgumentParser(
        description="Run Bob2Protocol tests with arguments.")
    parser.add_argument('--version_major', type=int,
                        default=1, help='Protocol version major')
    parser.add_argument('--version_minor', type=int,
                        default=0, help='Protocol version minor')
    parser.add_argument('--message_type', type=int,
                        default=1, help='Message type')
    parser.add_argument('--dest_ipv6', type=str,
                        default="2001:0db8:85a3:0000:0000:8a2e:0370:7334", help='Destination IPv6 address')
    parser.add_argument('--dest_port', type=int,
                        default=12345, help='Destination port')
    parser.add_argument('--source_ipv6', type=str,
                        default="2001:0db8:85a3:0000:0000:8a2e:0370:1111", help='Source IPv6 address')
    parser.add_argument('--source_port', type=int,
                        default=54321, help='Source port')
    parser.add_argument('--sequence_number', type=int,
                        default=42, help='Sequence number')
    parser.add_argument('--message_content', type=str,
                        default="Test Message", help='Message content')

    # Isolate known and unknown args
    args, unknown = parser.parse_known_args()
    return args, unknown


class TestBob2Protocol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global args
        args = get_args()[0]  # Parse arguments here
        cls.bob2 = Bob2Protocol(
            version_major=args.version_major, version_minor=args.version_minor)

    def test_message_build_and_parse(self):
        # Build the message
        message = self.bob2.build_message(
            message_type=args.message_type,
            dest_ipv6=args.dest_ipv6,
            dest_port=args.dest_port,
            source_ipv6=args.source_ipv6,
            source_port=args.source_port,
            sequence_number=args.sequence_number,
            message_content=args.message_content
        )

        # Parse the message back
        parsed_message = self.bob2.parse_message(message)

        # Assertions
        self.assertEqual(parsed_message["version_major"], args.version_major)
        self.assertEqual(parsed_message["version_minor"], args.version_minor)
        self.assertEqual(parsed_message["message_type"], args.message_type)
        self.assertEqual(ipaddress.IPv6Address(
            parsed_message["dest_ipv6"]), ipaddress.IPv6Address(args.dest_ipv6))
        self.assertEqual(parsed_message["dest_port"], args.dest_port)
        self.assertEqual(ipaddress.IPv6Address(
            parsed_message["source_ipv6"]), ipaddress.IPv6Address(args.source_ipv6))
        self.assertEqual(parsed_message["source_port"], args.source_port)
        self.assertEqual(
            parsed_message["sequence_number"], args.sequence_number)
        self.assertEqual(
            parsed_message["message_content"], args.message_content)


if __name__ == "__main__":
    args, unknown = get_args()
    # Pass only unittest-compatible arguments to unittest.main()
    sys.argv = [sys.argv[0]] + unknown
    unittest.main()
