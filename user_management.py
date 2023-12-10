import uuid
from passlib.hash import bcrypt
import sqlite3
from datetime import datetime
from email_validator import validate_email, EmailNotValidError
from flask_mail import Message, Mail  # Import Message and Mail for email sending
import secrets

# Generate a secret key for secure token generation
secret_key = secrets.token_hex(16)  # 32-character hexadecimal secret key

# Initialize the SQLite database
def initialize_database():
    # Connect to the SQLite database (using the name 'user_data.db' in the same directory)
    with sqlite3.connect('user_data.db') as conn:
        cursor = conn.cursor()

        # Create a table for users if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT NOT NULL,
                date_registered DATETIME NOT NULL,
                is_verified INTEGER NOT NULL
            )
        ''')

        # Commit the changes
        conn.commit()

# Initialize the database when this module is run
initialize_database()

mail = Mail()  # Initialize the mail object

def generate_password():
    return str(uuid.uuid4())

def hash_password(password):
    return bcrypt.using(rounds=12).hash(password)

def is_valid_email(email):
    try:
        v = validate_email(email)
        return v['email']
    except EmailNotValidError as e:
        return None

def register_user(username, email):
    # Validate email format
    valid_email = is_valid_email(email)
    if not valid_email:
        return "Invalid email format"

    # Continue with user registration
    password = generate_password()
    hashed_password = hash_password(password)

    with sqlite3.connect('user_data.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, email, date_registered, is_verified)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, hashed_password, email, datetime.now(), 0))
        conn.commit()

    # Send confirmation email
    send_confirmation_email(email, username)

    return password

# Rest of your code...

def send_confirmation_email(email, username):
    token = generate_confirmation_token(email)
    confirm_url = f"http://your-app.com/confirm/{token}"
    subject = "Confirm Your Email"
    body = f"Hi {username}, please click the link to confirm your email: {confirm_url}"
    send_email(email, subject, body)

def generate_confirmation_token(email):
    # Generate a confirmation token (you can use a library like itsdangerous)
    # This token will be embedded in the confirmation link sent to the user's email.
    return "your_confirmation_token"

def send_email(to, subject, body):
    # Use Flask-Mail or any other library to send emails
    message = Message(subject, recipients=[to], body=body)
    mail.send(message)
