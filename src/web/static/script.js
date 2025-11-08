// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tabName = btn.dataset.tab;

        // Remove active class from all tabs
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

        // Add active class to clicked tab
        btn.classList.add('active');
        document.getElementById(tabName).classList.add('active');
    });
});

// File input listeners
document.getElementById('encryptFile')?.addEventListener('change', (e) => {
    const fileName = e.target.files[0]?.name || 'No file selected';
    document.getElementById('encryptFileName').textContent = fileName;
});

document.getElementById('decryptFile')?.addEventListener('change', (e) => {
    const fileName = e.target.files[0]?.name || 'No file selected';
    document.getElementById('decryptFileName').textContent = fileName;
});

// Encrypt form submission
document.getElementById('encryptForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const file = document.getElementById('encryptFile').files[0];
    const key = document.getElementById('encryptKey').value;
    const algorithm = document.querySelector('input[name="encrypt_algo"]:checked').value;
    const statusDiv = document.getElementById('encryptStatus');

    if (!file) {
        showStatus(statusDiv, 'Please select a file', 'error');
        return;
    }

    if (!key) {
        showStatus(statusDiv, 'Please enter an encryption key', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('key', key);
    formData.append('algorithm', algorithm);

    try {
        showStatus(statusDiv, 'Encrypting file...', 'info');
        const response = await fetch('/api/encrypt', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (response.ok) {
            showStatus(statusDiv, `✓ ${data.message}`, 'success');
            document.getElementById('encryptForm').reset();
            document.getElementById('encryptFileName').textContent = 'No file selected';
        } else {
            showStatus(statusDiv, `✗ ${data.error}`, 'error');
        }
    } catch (error) {
        showStatus(statusDiv, `✗ Error: ${error.message}`, 'error');
    }
});

// Decrypt form submission
document.getElementById('decryptForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const file = document.getElementById('decryptFile').files[0];
    const key = document.getElementById('decryptKey').value;
    const algorithm = document.querySelector('input[name="decrypt_algo"]:checked').value;
    const statusDiv = document.getElementById('decryptStatus');

    if (!file) {
        showStatus(statusDiv, 'Please select an encrypted file', 'error');
        return;
    }

    if (!key) {
        showStatus(statusDiv, 'Please enter the decryption key', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('key', key);
    formData.append('algorithm', algorithm);

    try {
        showStatus(statusDiv, 'Decrypting file...', 'info');
        const response = await fetch('/api/decrypt', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (response.ok) {
            showStatus(statusDiv, `✓ ${data.message}`, 'success');
            document.getElementById('decryptForm').reset();
            document.getElementById('decryptFileName').textContent = 'No file selected';
        } else {
            showStatus(statusDiv, `✗ ${data.error}`, 'error');
        }
    } catch (error) {
        showStatus(statusDiv, `✗ Error: ${error.message}`, 'error');
    }
});

// Generate symmetric key
async function generateSymmetricKey() {
    const algorithm = document.querySelector('input[name="sym_algo"]:checked').value;
    const statusDiv = document.getElementById('symKeyStatus');
    const outputDiv = document.getElementById('symKeyOutput');

    try {
        showStatus(statusDiv, 'Generating key...', 'info');

        const response = await fetch('/api/generate-key', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ algorithm })
        });

        const data = await response.json();

        if (response.ok) {
            showStatus(statusDiv, `✓ ${algorithm.toUpperCase()} key generated successfully`, 'success');

            outputDiv.innerHTML = `
                <h4>${algorithm.toUpperCase()} Key</h4>
                <p>Keep this key safe! You'll need it to encrypt/decrypt files.</p>
                <div class="key-text">${escapeHtml(data.key)}</div>
                <button class="btn btn-copy" onclick="copyToClipboard('${escapeHtml(data.key)}')">
                    Copy Key
                </button>
                <button class="btn btn-download" onclick="downloadKey('${escapeHtml(data.key)}', '${algorithm}_key.txt')">
                    Download Key
                </button>
            `;
            outputDiv.classList.add('show');
        } else {
            showStatus(statusDiv, `✗ ${data.error}`, 'error');
        }
    } catch (error) {
        showStatus(statusDiv, `✗ Error: ${error.message}`, 'error');
    }
}

// Generate RSA keypair
async function generateRSAKeypair() {
    const statusDiv = document.getElementById('rsaKeyStatus');
    const outputDiv = document.getElementById('rsaKeyOutput');

    try {
        showStatus(statusDiv, 'Generating RSA keypair (this may take a moment)...', 'info');

        const response = await fetch('/api/generate-keypair', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (response.ok) {
            showStatus(statusDiv, '✓ RSA keypair generated successfully', 'success');

            outputDiv.innerHTML = `
                <h4>RSA Private Key</h4>
                <p>⚠️ Keep this PRIVATE KEY safe! Never share it!</p>
                <div class="key-text">${escapeHtml(data.private_key)}</div>
                <button class="btn btn-copy" onclick="copyToClipboard(\`${escapeHtml(data.private_key)}\`)">
                    Copy Private Key
                </button>
                <button class="btn btn-download" onclick="downloadKey(\`${escapeHtml(data.private_key)}\`, 'rsa_private.pem')">
                    Download Private Key
                </button>

                <hr style="margin: 20px 0; border: none; border-top: 2px solid #E0E0E0;">

                <h4>RSA Public Key</h4>
                <p>You can safely share this PUBLIC KEY with others.</p>
                <div class="key-text">${escapeHtml(data.public_key)}</div>
                <button class="btn btn-copy" onclick="copyToClipboard(\`${escapeHtml(data.public_key)}\`)">
                    Copy Public Key
                </button>
                <button class="btn btn-download" onclick="downloadKey(\`${escapeHtml(data.public_key)}\`, 'rsa_public.pem')">
                    Download Public Key
                </button>
            `;
            outputDiv.classList.add('show');
        } else {
            showStatus(statusDiv, `✗ ${data.error}`, 'error');
        }
    } catch (error) {
        showStatus(statusDiv, `✗ Error: ${error.message}`, 'error');
    }
}

// Helper functions
function showStatus(element, message, type) {
    element.textContent = message;
    element.className = `status-message show ${type}`;

    // Auto-hide info and warning messages after 5 seconds
    if (type === 'info' || type === 'warning') {
        setTimeout(() => {
            element.classList.remove('show');
        }, 5000);
    }
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showStatus(document.querySelector('.status-message') || document.body, '✓ Copied to clipboard', 'success');
    }).catch(err => {
        alert('Failed to copy: ' + err);
    });
}

function downloadKey(content, filename) {
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content));
    element.setAttribute('download', filename);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}
