# protocol/optional_headers.py

import struct
import time
import socket


class LEOOptionalHeaders:
    def __init__(self, timestamp=None, hop_count=255, priority=0, encryption_algo="None"):
        self.timestamp = timestamp if timestamp else int(time.time())
        self.hop_count = hop_count
        self.priority = priority
        self.encryption_algo = encryption_algo

    def build_optional_header(self):
        header = struct.pack("!I", self.timestamp)  # 4 bytes for timestamp
        header += struct.pack("!B", self.hop_count)  # 1 byte for hop count
        header += struct.pack("!B", self.priority)  # 1 byte for priority
        # 16 bytes for encryption_algo
        header += self.encryption_algo.encode('utf-8').ljust(16, b'\0')
        return header

    def parse_optional_header(self, raw_data):
        timestamp = struct.unpack("!I", raw_data[:4])[0]
        hop_count = struct.unpack("!B", raw_data[4:5])[0]
        priority = struct.unpack("!B", raw_data[5:6])[0]
        encryption_algo = raw_data[6:22].decode('utf-8').rstrip('\0')
        return {
            "timestamp": timestamp,
            "hop_count": hop_count,
            "priority": priority,
            "encryption_algo": encryption_algo
        }
