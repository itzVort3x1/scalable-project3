# handshake.py
import random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

P = 23  # Diffie-Hellman prime number
G = 5   # Diffie-Hellman generator

class Handshake:
    def __init__(self):
        self.shared_key = None

    def generate_keys(self):
        private_key = random.randint(1, P - 1)
        public_key = pow(G, private_key, P)
        return private_key, public_key

    def establish_shared_key(self, other_public_key, private_key):
        shared_secret = pow(other_public_key, private_key, P)
        self.shared_key = sha256(str(shared_secret).encode()).digest()
        return self.shared_key

    def encrypt_message(self, message):
        cipher = AES.new(self.shared_key, AES.MODE_CBC)
        iv = cipher.iv
        cipher_text = cipher.encrypt(pad(message.encode(), AES.block_size))
        return iv + cipher_text

    def decrypt_message(self, iv_cipher_text):
        iv = iv_cipher_text[:16]
        cipher_text = iv_cipher_text[16:]
        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(cipher_text), AES.block_size).decode('utf-8')
        return decrypted_message
