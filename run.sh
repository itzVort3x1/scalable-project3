#!/bin/zsh

python3 -m venv venv

source ./venv/bin/activate

pip3 install -r requirements.txt




#to start the server
python3 main.py --version_major 1 --version_minor 0 --message_type 0 \
--dest_ip "192.168.165.27" --dest_port 12345 \
--source_ip "10.20.11.112" --source_port 54321 \
--sequence_number 1 --message_content "Hello, LEO Satellite\!" --mode server

# to start the client
python3 main.py --version_major 1 --version_minor 0 --message_type 0 \
--dest_ip "2001:0db8:85a3:0000:0000:8a2e:0370:7334" --dest_port 12345 \
--source_ip "2001:0db8:85a3:0000:0000:8a2e:0370:1111" --source_port 54321 \
--sequence_number 1 --message_content "Hello, LEO Satellite\!" --mode client


# to test
PYTHONPATH=$(pwd)/src python3 test/test_bob2_protocol.py \
--version_major 1 --version_minor 0 --message_type 1 \
--dest_ipv6 "2001:0db8:85a3:0000:0000:8a2e:0370:7334" --dest_port 12345 \
--source_ipv6 "2001:0db8:85a3:0000:0000:8a2e:0370:1111" --source_port 54321 \
--sequence_number 42 --message_content "Test Message"


