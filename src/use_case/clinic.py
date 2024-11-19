import base64
import random
import socket
import sys
import os
import threading
import time
import json

# set project as root folder
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.append(project_root)

from src.protocol.implementation_testing_files.data_generator import mock_smartwatch_data_return_str
from src.protocol.jarvis import Jarvis

class Clinic:
    default_server_port = 12345
    default_client_port = 54321

    def __init__(self, name, numberID, version_major):
        self.name = name
        self.numberID = numberID
        self.version_major = version_major
        self.version_minor = version_major
        self.node = Jarvis(Clinic.default_server_port, Clinic.default_client_port)
        self.messages_received = []  # Track received messages
        self.workload = 0  # Track current workload
        self.save_messages = False  # Flag to determine whether to save messages
        # Set the receive callback for the node to handle received messages
        self.node.set_receive_callback(self.receive_message)

    def get_name(self):
        return self.name
    
    def get_numberID(self):
        return self.numberID
    
    def update_version(self, version_major, version_minor):
        self.version_major = version_major
        self.version_minor = version_minor

    def increase_workload(self):
        self.workload += 1
        if 1 <= self.workload <= 3:
            print(f"Clinic {self.name} is currently idle.")
        elif 4 <= self.workload <= 6:
            print(f"Clinic {self.name} is currently occupied with some tasks.")
        elif self.workload >= 7:
            print(f"Clinic {self.name} is now busy.")

    def decrease_workload(self):
        if self.workload > 0:
            self.workload -= 1

    @staticmethod
    def get_local_ip(public_address="8.8.8.8", public_port=80):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((public_address, public_port))
                return s.getsockname()[0]
        except Exception as e:
            print(f"Error to connect public address {public_address}:{public_port} - {e}")
            return None

    def message(self):
        while True:
            print("\nOptions:")
            print("1. Enter text")
            print("2. Enter file path")
            choice = input("Enter your choice: ")

            if choice == "1":
                user_input = input("Enter your text: ")
                return user_input
            elif choice == "2":
                file_path = input("Enter file path: ")
                if os.path.isfile(file_path):
                    with open(file_path, "rb") as f:
                        file_data = f.read()
                        if file_path.endswith(('.txt', '.md', '.csv')):
                            return file_data.decode('utf-8')
                        else:
                            return base64.b64encode(file_data).decode('utf-8')
                else:
                    print("Invalid file path. Please try again.")
            else:
                print("Invalid choice. Please enter 1 or 2.")

    def start(self):
        local_ip = self.get_local_ip()
        print(f"Local IP: {local_ip}")

        ip_list = []
        
        if local_ip in self.node.adjacency_list:
            for index, (ip, distance) in enumerate(self.node.adjacency_list[local_ip].items(), start=1):
                # Real latency maybe optimized by dijkstra algorithm 
                print(f"{index}. Clinic {ip}: Latency {distance}")
                ip_list.append(ip)
        else:
            print("Local address not in adjacency_list")
            for index, ip in enumerate(self.node.adjacency_list, start=1):
                # exclude self
                if ip == local_ip:
                    continue
                print(f"{index}. Clinic {ip}")
                ip_list.append(ip)
        
        self.ava_ip_list = ip_list
                
        print()
        print('Choose your target clinic')
        
        while True:
            try:
                choice = int(input("Enter the number: "))  # User inputs a number
                if 1 <= choice <= len(ip_list):
                    selected_ip = ip_list[choice - 1]
                    print(f"You have selected Clinic {selected_ip}")
                    break
                else:
                    print("Invalid choice. Please enter a valid number.")
            except ValueError:
                print("Invalid input. Please enter a number.")
        
        # Start a receiver server
        threading.Thread(target=self.node.start_receiver, daemon=True).start()
        
        # Start sending messages to the selected clinic
        self.interactive_cli(selected_ip)
        
    def interactive_cli(self, selected_ip):
        while True:
            print("\nOptions:")
            print("1. Send a message")
            print("2. View received messages")
            print("3. View current status")
            print("4. View clinic information")
            print("5. Toggle save messages")
            print("6. Enable forward smartwatch data to other clinics")
            print("7. Exit")
            choice = input("Enter your choice: ")

            if choice == "1":
                threading.Thread(target=self.send_message_thread, args=(selected_ip,), daemon=True).start()
            elif choice == "2":
                self.view_received_messages()
            elif choice == "3":
                self.view_current_status()
            elif choice == "4":
                self.view_clinic_info()
            elif choice == "5":
                self.toggle_save_messages()
            elif choice == "6":
                self.enable_forward_smartwatch_data()
            elif choice == "7":
                print("Exiting...")
                break
            else:
                print("Invalid choice.")

    def send_message_thread(self, selected_ip):
        message_content = self.message()
        self.increase_workload()  # Increase workload when sending a message
        self.node.send_message(selected_ip, message_content)
        if self.save_messages:
            self.save_message_to_file(message_content)  # Save the sent message to a file if enabled
        self.decrease_workload()  # Decrease workload after sending a message

    def save_message_to_file(self, message_content):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"message_{timestamp}.txt"
        filepath = os.path.join("messages", filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            f.write(message_content)
        print(f"Message saved to {filepath}")

    def toggle_save_messages(self):
        self.save_messages = not self.save_messages
        status = "enabled" if self.save_messages else "disabled"
        print(f"Save messages is now {status}.")

    def view_received_messages(self):
        if self.messages_received:
            print("\nReceived Messages:")
            for idx, msg in enumerate(self.messages_received, start=1):
                if len(msg) > 150:
                    print(f"{idx}. [Truncated] {msg[:150]}... (truncated)")
                elif msg.startswith('data:image') or msg.startswith('data:application'):
                    print(f"{idx}. [File] {msg[:50]}... (truncated)" )
                else:
                    print(f"{idx}. [Text] {msg}")
        else:
            print("No messages received yet.")

    def view_current_status(self):
        if 1 <= self.workload <= 3:
            status = "idle"
        elif 4 <= self.workload <= 6:
            status = "occupied with some tasks"
        elif self.workload >= 7:
            status = "busy"
        else:
            status = "unknown"
        print(f"Clinic {self.name} is currently {status} with a workload of {self.workload}.")

    def view_clinic_info(self):
        local_ip = self.get_local_ip()
        print(f"\nClinic Information:")
        print(f"Name: {self.name}")
        print(f"ID: {self.numberID}")
        print(f"Version: {self.version_major}.{self.version_minor}")
        print(f"IP Address: {local_ip}")

    def receive_message(self, message):
        self.messages_received.append(message)
        if self.save_messages:
            self.save_message_to_file(message)

    def forward_smartwatch_data(self):
        # Run every 5 minutes
        
        while True:
            if self.forward_smartwatch_flag:
                smartwatch_data_str = mock_smartwatch_data_return_str()
                # Send smartwatch data to clinic in self.ava_ip_list
                for ip in self.ava_ip_list:
                    self.increase_workload()
                    self.node.send_message(ip, smartwatch_data_str)
                    self.decrease_workload()
                    if self.save_messages:
                        self.save_message_to_file(smartwatch_data_str)
            time.sleep(5 * 60)
        
        
    def enable_forward_smartwatch_data(self):
        self.forward_smartwatch_flag = True
        self.forward_smartwatch_thread = threading.Thread(target=self.forward_smartwatch_data, daemon=True)
        self.forward_smartwatch_thread.start()
        
    def disable_forward_smartwatch_data(self):
        self.forward_smartwatch_flag = False
        
    def start_random(seed):
        #print some random content
        random.seed(seed)
        print(random.random())
        print(random.randint(1, 100))
        print(random.choice(['a', 'b', 'c']))
        print(random.choices(['a', 'b', 'c'], k=2))
        print(random.sample(['a', 'b', 'c'], 2))
# main
if __name__ == "__main__":
    clinic = Clinic('yumo', '001', '0.01')
    clinic.start_random(1)
