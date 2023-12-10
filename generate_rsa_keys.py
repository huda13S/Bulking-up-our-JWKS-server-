# generate_rsa_keys.py

import jwt
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import sqlite3
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from werkzeug.security import generate_password_hash

# Load the AES key from the environment variable
aes_key = os.environ.get("NOT_MY_KEY")

# Check if NOT_MY_KEY is set
if aes_key is None:
    print("ERROR: The environment variable 'NOT_MY_KEY' is not set.")
    # Optionally, you might want to exit the script or handle the absence of the key.
    exit()

def connect_to_database():
    return sqlite3.connect('totally_not_my_privateKeys.db')

# Function to initialize the database and create necessary tables
def initialize_database():
    with connect_to_database() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()

# Call the function to initialize the database and create tables
initialize_database()

# Function to encrypt private key
def encrypt_private_key(private_key):
    cipher = Cipher(algorithms.AES(aes_key.encode()), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_private_key = encryptor.update(private_key.encode()) + encryptor.finalize()
    return encrypted_private_key

# Function to decrypt private key
def decrypt_private_key(encrypted_private_key):
    cipher = Cipher(algorithms.AES(aes_key.encode()), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_private_key = decryptor.update(encrypted_private_key) + decryptor.finalize()
    return decrypted_private_key.decode()

# Function to generate and store RSA key
def generate_and_store_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize the public key to PEM format
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt the private key before storing
    encrypted_private_key = encrypt_private_key(private_key_pem.decode())

    # Store the encrypted private key and associated metadata in the database
    with connect_to_database() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO keys (key, exp) VALUES (?, ?)
        ''', (encrypted_private_key, int(time.time()) + 3600))  # Set expiration time (1 hour)
        conn.commit()

# Function to register a new user
def register_user(username, email):
    password = str(uuid.uuid4())  # Generate a secure password using UUIDv4
    hashed_password = generate_password_hash(password)  # Hash the password
    with connect_to_database() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)
        ''', (username, hashed_password, email))
        conn.commit()
    return password

# Function to log authentication requests
def log_authentication_request(request_ip, user_id=None):
    with connect_to_database() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)
        ''', (request_ip, user_id))
        conn.commit()

# Function to generate JWT token
def generate_jwt_token(user_id):
    # Generate a JWT token with the user_id as the payload
    return jwt.encode({"user_id": user_id}, "09po90op", algorithm="HS256")

# Main function to generate and store RSA key
if __name__ == "__main__":
    generate_and_store_rsa_key()
