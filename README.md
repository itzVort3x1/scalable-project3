# Bob2

Created for the management of a protocol for Scalable Computing 2024. This should be entirely collaborative, and the initial version is mostly built as a jumping off point for the class (or whoever decides to use Bob2 as their protocol).

An example library for this is given for Python, please feel free to make libraries for other languages! The important element is that the protocol details are followed the same in every language.

## Protocol Summary

| Byte 0                           | Byte 1                           | Byte 2                           | Byte 3-4 | Bytes 5-20   | Bytes 21-22 | Bytes 23-27                                                                            | Bytes 28-31 | Bytes 32+ |
| -------------------------------- | -------------------------------- | ---|-------------------------------- | ------------ | ----------- | -------------------------------------------------------------------------------------- | ----------- | --------- |
| Bob2 major version - EG 1 in 1.0 | Bob2 minor version - EG 0 in 1.0 | Message Type - more detail below | Packet number - if the message is not split into multiple packets, this should be set to 0, otherwise, counting begins at 1 |Destination IPv6 Address | Destination Port number | Length of message in bytes (allows up to a terabyte of data to be sent in one message) | CRC32 Checksum |  Message (encoded in UTF-8)        |
|                                  |                                  |                                  |              |             |                                                                                        |             |           |

Message types - up to 256 types in Bob2 v0.0.

| Value of Byte 32 | Message type                             |
| ---------------- | ---------------------------------------- |
| 0                | Sending Message           |
| 1                | ACK |

## Protocol Requirements

1. Bob2 Version - format X.X
2. Contain message type
    1. Sending to ground station
    2. ACK returning from ground station
3. Describe message length in bytes
4. Contain message destination - IPv6?
5. Contain packet number if the message is sent in multiple sections
6. Message content bytes!

## Protocol Details

Bob2 v0.2 has the following assumptions, based on the simplest understanding of a LEO system

1. The network is built up of 3 component types
    1. Earth node - in a standard use case, this is a Starlink (or similar) customer with a satellite to connect to the LEO satellites.
    2. Satellites - in all cases, these are the actual Low Earth Orbit satellites. In this assignment, these are what are represented by the raspberry pis. They receive messages from source nodes, which are passed between satellites until they can find the destination node.
2. Any simulated delays/lags/latency/jitter (to recreate an LEO system) is handled by the code sending/receiving messages, and is not handled within the protocol.
3. We shouldn't get more than 256.256 versions of Bob2 (I'm hoping)
4. Retries are also handled outside of the protocol, making use of the ACK within the protocol (feel free to add more sections to handle this).
5. Routing between satellites (ISL) is handled outside of the protocol.
6. Message integrity is verified using a CRC32 checksum of the message content.
7. Messages can be sent in multiple packets if required - up to 65,535 packets. If multiple packets are not being used, set the bytes for this to 0.


## Potential Areas for improvement

1. ~~Checksum to check for message corruption.~~ ✓ Implemented
2. Encrypting the message.

