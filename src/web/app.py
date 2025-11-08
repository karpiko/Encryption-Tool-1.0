"""Flask web application for encryption tool."""

import os
import sys
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import tempfile
from pathlib import Path
import io
import base64
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, will use os.environ

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from encryptors import FernetEncryptor, AESEncryptor, RSAEncryptor

# Create Flask app
app = Flask(__name__,
            template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
            static_folder=os.path.join(os.path.dirname(__file__), 'static'))

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# Allowed extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'zip', 'enc', 'key', 'pem'}

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS or True

def send_encrypted_file_email(sender_email, receiver_email, encrypted_file_path, original_filename, access_code):
    """
    Send encrypted file via email with access information.

    Requires SMTP credentials configured via environment variables:
    - SMTP_SERVER: SMTP server address (default: smtp.gmail.com)
    - SMTP_PORT: SMTP port (default: 587)
    - SMTP_USERNAME: SMTP username/email
    - SMTP_PASSWORD: SMTP password or app-specific password

    For Gmail: Use app-specific password (not your regular password)
    See setup instructions in EMAIL_SETUP.md
    """
    try:
        # Get SMTP configuration from environment variables
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        smtp_username = os.getenv('SMTP_USERNAME', '')
        smtp_password = os.getenv('SMTP_PASSWORD', '')

        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = f'Secure File Transfer: {original_filename}'

        # Email body
        body = f"""
Hello,

You have received a securely encrypted file: {original_filename}

IMPORTANT SECURITY INFORMATION:
- This file is encrypted and can only be accessed with the correct decryption key
- Keep your access code safe and do not share it
- The decryption key should be provided separately by the sender

Access Code: {access_code}

The encrypted file is attached to this email. To decrypt it:
1. Use the Secure File Encryption Tool
2. Upload the encrypted file
3. Enter the encryption key (provided by sender through a separate channel)
4. Download your decrypted file

For security reasons:
- The sender should provide the decryption key through a separate, secure channel
- This ensures end-to-end encryption and maximum security
- Never share your decryption key via email

Best regards,
Secure File Encryption Tool
"""

        msg.attach(MIMEText(body, 'plain'))

        # Attach encrypted file
        with open(encrypted_file_path, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename={original_filename}.enc',
            )
            msg.attach(part)

        # Check if SMTP credentials are configured
        if not smtp_username or not smtp_password:
            return False, "Email sending not configured. Please set SMTP credentials in environment variables (SMTP_USERNAME, SMTP_PASSWORD). See EMAIL_SETUP.md for instructions."

        # Send email via SMTP
        try:
            with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.send_message(msg)
            return True, f"Email sent successfully to {receiver_email}"
        except smtplib.SMTPAuthenticationError:
            return False, "SMTP authentication failed. Check your SMTP_USERNAME and SMTP_PASSWORD. For Gmail, use an app-specific password."
        except smtplib.SMTPException as e:
            return False, f"SMTP error: {str(e)}"
        except Exception as e:
            return False, f"Failed to send email: {str(e)}"

    except Exception as e:
        return False, f"Error preparing email: {str(e)}"

@app.route('/')
def index():
    """Render main page."""
    return render_template('index.html')

@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    """Generate an encryption key."""
    try:
        data = request.json
        algorithm = data.get('algorithm', 'fernet').lower()

        if algorithm == 'fernet':
            key = FernetEncryptor.generate_key()
            # Fernet keys are already base64-encoded
            key_str = key.decode('utf-8')
        elif algorithm == 'aes':
            key = AESEncryptor.generate_key()
            # AES keys are raw bytes, encode as base64 for transport
            key_str = base64.b64encode(key).decode('utf-8')
        else:
            return jsonify({'error': 'Invalid algorithm'}), 400

        # Return key as downloadable text
        return jsonify({
            'success': True,
            'key': key_str,
            'algorithm': algorithm
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-keypair', methods=['POST'])
def generate_keypair():
    """Generate RSA keypair."""
    try:
        private_key, public_key = RSAEncryptor.generate_key_pair()

        # Convert to PEM format strings
        from cryptography.hazmat.primitives import serialization

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return jsonify({
            'success': True,
            'private_key': private_pem,
            'public_key': public_pem
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/encrypt', methods=['POST'])
def encrypt_file():
    """Encrypt a file and optionally send via email."""
    temp_input = None
    temp_output = None

    try:
        # Check if file and key are provided
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        if 'key' not in request.form:
            return jsonify({'error': 'No key provided'}), 400

        file = request.files['file']
        key_data = request.form.get('key')
        algorithm = request.form.get('algorithm', 'fernet').lower()
        sender_email = request.form.get('sender_email', '').strip()
        receiver_email = request.form.get('receiver_email', '').strip()

        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        temp_input = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_input_{filename}')
        file.save(temp_input)

        # Prepare key
        if algorithm == 'fernet':
            if isinstance(key_data, str):
                key = key_data.encode()
            else:
                key = key_data
            encryptor = FernetEncryptor
        elif algorithm == 'aes':
            # AES keys from API are base64-encoded
            if isinstance(key_data, str):
                try:
                    key = base64.b64decode(key_data)
                except:
                    # If not base64, treat as raw key
                    key = key_data.encode()
            else:
                key = key_data
            encryptor = AESEncryptor
        else:
            if os.path.exists(temp_input):
                os.remove(temp_input)
            return jsonify({'error': 'Invalid algorithm'}), 400

        # Encrypt file
        temp_output = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_output_{filename}.enc')
        encryptor.encrypt_file(temp_input, temp_output, key)

        # Generate one-time access code
        access_code = secrets.token_urlsafe(32)

        # Check if email sending is requested
        if sender_email and receiver_email:
            # Send via email
            success, message = send_encrypted_file_email(
                sender_email,
                receiver_email,
                temp_output,
                filename,
                access_code
            )

            # Clean up temp files
            if os.path.exists(temp_input):
                os.remove(temp_input)
            if os.path.exists(temp_output):
                os.remove(temp_output)

            if success:
                return jsonify({
                    'success': True,
                    'message': f'File encrypted and email sent to {receiver_email}. Access code: {access_code}',
                    'access_code': access_code
                }), 200
            else:
                return jsonify({'error': message}), 500
        else:
            # Download directly
            output_filename = f"{filename}.enc"

            # Read the file data before deleting
            with open(temp_output, 'rb') as f:
                encrypted_data = f.read()

            # Clean up temp files
            if os.path.exists(temp_input):
                os.remove(temp_input)
            if os.path.exists(temp_output):
                os.remove(temp_output)

            # Return the encrypted file
            return send_file(
                io.BytesIO(encrypted_data),
                as_attachment=True,
                download_name=output_filename,
                mimetype='application/octet-stream'
            )

    except Exception as e:
        # Clean up on error
        if temp_input and os.path.exists(temp_input):
            os.remove(temp_input)
        if temp_output and os.path.exists(temp_output):
            os.remove(temp_output)
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_file():
    """Decrypt a file."""
    temp_input = None
    temp_output = None

    try:
        # Check if file and key are provided
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        if 'key' not in request.form:
            return jsonify({'error': 'No key provided'}), 400

        file = request.files['file']
        key_data = request.form.get('key')
        algorithm = request.form.get('algorithm', 'fernet').lower()

        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        temp_input = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_input_{filename}')
        file.save(temp_input)

        # Prepare key
        if algorithm == 'fernet':
            if isinstance(key_data, str):
                key = key_data.encode()
            else:
                key = key_data
            decryptor = FernetEncryptor
        elif algorithm == 'aes':
            # AES keys from API are base64-encoded
            if isinstance(key_data, str):
                try:
                    key = base64.b64decode(key_data)
                except:
                    # If not base64, treat as raw key
                    key = key_data.encode()
            else:
                key = key_data
            decryptor = AESEncryptor
        else:
            if os.path.exists(temp_input):
                os.remove(temp_input)
            return jsonify({'error': 'Invalid algorithm'}), 400

        # Decrypt file
        temp_output = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_output_{filename}')
        decryptor.decrypt_file(temp_input, temp_output, key)

        # Send decrypted file to user
        # Remove .enc or other extension and use original filename
        output_filename = filename.rsplit('.', 1)[0] if '.' in filename else filename

        # Read the file data before deleting
        with open(temp_output, 'rb') as f:
            decrypted_data = f.read()

        # Clean up temp files
        if os.path.exists(temp_input):
            os.remove(temp_input)
        if os.path.exists(temp_output):
            os.remove(temp_output)

        # Return the decrypted file
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=output_filename,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        # Clean up on error
        if temp_input and os.path.exists(temp_input):
            os.remove(temp_input)
        if temp_output and os.path.exists(temp_output):
            os.remove(temp_output)
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

def run_app(debug=False, port=8000):
    """Run the Flask application."""
    print("\n" + "="*60)
    print("  File Encryption Tool - Web GUI")
    print("="*60)
    print(f"\n🌐 Opening application at: http://127.0.0.1:{port}")
    print("🔐 Secure File Encryption\n")

    # Open browser
    import webbrowser
    webbrowser.open(f'http://127.0.0.1:{port}')

    # Run app
    app.run(debug=debug, port=port, host='127.0.0.1')

if __name__ == '__main__':
    run_app()
