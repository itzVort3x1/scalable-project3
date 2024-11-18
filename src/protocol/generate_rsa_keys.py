from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_keys():
    """Generate RSA key pair and save to PEM files."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Standard public exponent
        key_size=2048,  # Key size in bits
    )

    # Save private key to a file
    with open("private_key.pem", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),  # No password for simplicity
            )
        )

    # Extract public key from the private key
    public_key = private_key.public_key()

    # Save public key to a file
    with open("public_key.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


generate_rsa_keys()
