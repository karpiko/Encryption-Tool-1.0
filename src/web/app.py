"""Flask web application for encryption tool."""

import os
import sys
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import tempfile
from pathlib import Path
import io

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
        elif algorithm == 'aes':
            key = AESEncryptor.generate_key()
        else:
            return jsonify({'error': 'Invalid algorithm'}), 400

        # Return key as downloadable text
        return jsonify({
            'success': True,
            'key': key.decode('utf-8'),
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
    """Encrypt a file."""
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
            encryptor = FernetEncryptor
        elif algorithm == 'aes':
            if isinstance(key_data, str):
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

        # Send encrypted file to user
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
            if isinstance(key_data, str):
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
    print("🔐 Davenport University - Secure File Encryption\n")

    # Open browser
    import webbrowser
    webbrowser.open(f'http://127.0.0.1:{port}')

    # Run app
    app.run(debug=debug, port=port, host='127.0.0.1')

if __name__ == '__main__':
    run_app()
