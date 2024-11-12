# src/protocol/bob2_protocol.py

import struct
import socket
import zlib
from protocol.necessary_headers import Bob2Headers


class Bob2Protocol:
    def __init__(self, version_major=0, version_minor=0):
        self.version_major = version_major
        self.version_minor = version_minor

    def build_message(self, message_type, dest_ipv6, dest_port, source_ipv6, source_port, sequence_number, message_content):
        # Create the header using Bob2Headers
        header = Bob2Headers(
            version_major=self.version_major,
            version_minor=self.version_minor,
            message_type=message_type,
            dest_ipv6=dest_ipv6,
            dest_port=dest_port,
            source_ipv6=source_ipv6,
            source_port=source_port,
            sequence_number=sequence_number
        ).build_header()

        # Calculate checksum
        checksum = zlib.crc32(message_content.encode('utf-8'))
        checksum_bytes = struct.pack('!I', checksum)

        # Build the full message
        message_length = len(message_content)
        length_bytes = message_length.to_bytes(5, byteorder='big')

        full_message = header + length_bytes + \
            checksum_bytes + message_content.encode('utf-8')
        return full_message

    def parse_message(self, raw_data):
        # Parse the header
        header_data = raw_data[:47]  # Header size is 47 bytes
        header_info = Bob2Headers().parse_header(header_data)

        # Parse the rest of the message
        message_length = int.from_bytes(raw_data[47:52], byteorder='big')
        expected_checksum = struct.unpack('!I', raw_data[52:56])[0]
        message_content = raw_data[56:56 + message_length]
        actual_checksum = zlib.crc32(message_content)

        if expected_checksum != actual_checksum:
            raise ValueError("Checksum verification failed")

        # Add parsed message content to the header info
        header_info.update({
            "message_length": message_length,
            "checksum": expected_checksum,
            "message_content": message_content.decode('utf-8'),
        })

        return header_info
