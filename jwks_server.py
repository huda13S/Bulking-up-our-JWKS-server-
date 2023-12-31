from flask import Flask, request, jsonify
from generate_rsa_keys import register_user, log_authentication_request, generate_jwt_token
from werkzeug.security import check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from user_management import send_confirmation_email
from flask_mail import Mail, Message
from logging_config import configure_logging
from flask_bcrypt import Bcrypt  # Add this import statement

app = Flask(__name__)
limiter = Limiter(app, headers_enabled=True)
bcrypt = Bcrypt(app)  # Initialize Flask-Bcrypt

# Gmail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'hayalsuleman@gmail.com'
app.config['MAIL_PASSWORD'] = 'psal zxui jljt tyun'  # Use the password for the specified Gm$
app.config['MAIL_DEFAULT_SENDER'] = 'hayalsuleman@gmail.com'

# Initialize Flask-Mail
mail = Mail(app)

# Configure logging
configure_logging()

# Endpoint for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', 'huda')
    email = data.get('email', 'hayalsuleman@gmail.com')

    if not username or not email:
        return jsonify({"error": "Username and email are required"}), 400

    result = register_user(username, email)

    if "error" in result:
        return jsonify({"error": result["error"]}), 400

    send_confirmation_email(email, username)

    return jsonify({"message": "Registration successful"}), 201
# Endpoint for user authentication
@app.route('/auth', methods=['POST'])
@limiter.limit("10 per second")
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    request_ip = request.remote_addr

    # Log information about the request
    app.logger.info(f"Authentication request from IP {request_ip} for username {username}")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_password = bcrypt.generate_password_hash("salman223434").decode('utf-8')

    if bcrypt.check_password_hash(hashed_password, password):
        log_authentication_request(request_ip, user_id=1)
        jwt_token = generate_jwt_token(user_id=1)
        return jsonify({"message": "Authentication successful", "jwt_token": jwt_token}), 200
    else:
        return jsonify({"error": "Authentication failed"}), 401

# ... Other endpoints ...

if __name__ == '__main__':
    # Test email configuration
    with app.app_context():
        try:
            message = Message("Test Email", sender=app.config['MAIL_DEFAULT_SENDER'], recipi$
            message.body = "This is a test email from your Flask app."
            mail.send(message)
            print("Email sent successfully!")
        except Exception as e:
            print(f"Email could not be sent. Error: {str(e)}")

    app.run(debug=True, host='0.0.0.0', port=8080)
