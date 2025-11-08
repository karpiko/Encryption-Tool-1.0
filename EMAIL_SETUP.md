# Email Configuration Guide

This guide will help you set up email sending functionality for the File Encryption Tool.

## Overview

The web interface includes optional email sharing - users can send encrypted files directly to recipients via email. To enable this feature, you need to configure SMTP credentials.

## Prerequisites

- A Gmail account, or access to another SMTP server
- For Gmail users: Your regular Gmail password won't work with this tool; you'll need an "App Password"

## Setup Instructions

### Option 1: Gmail (Recommended)

Gmail requires app-specific passwords for security. Follow these steps:

#### Step 1: Enable 2-Step Verification
1. Go to [myaccount.google.com](https://myaccount.google.com)
2. Click "Security" in the left menu
3. Scroll to "How you sign in to Google"
4. Click "2-Step Verification" and complete the setup

#### Step 2: Generate App Password
1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Select "Mail" as the app
3. Select "Windows Computer" (or your device type)
4. Google will generate a 16-character app password
5. Copy this password - you'll use it in the next step

#### Step 3: Configure Environment Variables
1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and fill in your details:
   ```
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your-email@gmail.com
   SMTP_PASSWORD=your-16-character-app-password
   ```

3. **Important**: Keep `.env` secret! It's already in `.gitignore` to prevent accidental commits.

### Option 2: Other Email Providers

If you're using a different email provider (Outlook, Yahoo, SendGrid, etc.), configure accordingly:

#### Example: Outlook
```
SMTP_SERVER=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_USERNAME=your-email@outlook.com
SMTP_PASSWORD=your-password
```

#### Example: SendGrid
```
SMTP_SERVER=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=SG.your-sendgrid-api-key
```

#### Example: AWS SES
```
SMTP_SERVER=email-smtp.region.amazonaws.com
SMTP_PORT=587
SMTP_USERNAME=your-ses-username
SMTP_PASSWORD=your-ses-password
```

## Installation

After configuring `.env`, install the required dependency:

```bash
pip install python-dotenv
```

Or update all dependencies:
```bash
pip install -r requirements.txt
```

## Testing Email Functionality

### Test via Web Interface

1. Start the web application:
   ```bash
   python3 web_main.py
   ```

2. The application will open at `http://127.0.0.1:8000`

3. In the **Encrypt** tab:
   - Select a file to encrypt
   - Choose your encryption algorithm
   - Enter "Your Email" (sender address)
   - Enter "Recipient Email" (recipient address)
   - Click "Encrypt and Send via Email"

4. Check if the recipient received the email with the encrypted file

### Test via Python Script

Create a test script `test_email.py`:

```python
import os
from src.web.app import send_encrypted_file_email

# Create a test encrypted file
test_file = "/tmp/test_encrypted.enc"
with open(test_file, 'w') as f:
    f.write(b"gAAAAABnEX...")

# Test email sending
success, message = send_encrypted_file_email(
    sender_email="sender@gmail.com",
    receiver_email="recipient@gmail.com",
    encrypted_file_path=test_file,
    original_filename="test.txt",
    access_code="ABC123XYZ"
)

print(f"Success: {success}")
print(f"Message: {message}")
```

Run it:
```bash
python3 test_email.py
```

## Troubleshooting

### "Email sending not configured"
- **Problem**: SMTP_USERNAME or SMTP_PASSWORD not set
- **Solution**:
  1. Verify `.env` file exists in project root
  2. Check that SMTP_USERNAME and SMTP_PASSWORD are filled
  3. Reinstall requirements: `pip install -r requirements.txt`

### "SMTP authentication failed"
- **Problem**: Incorrect credentials
- **Solution**:
  - For Gmail: Ensure you're using an **App Password**, not your regular password
  - Verify email address is correct
  - Check password is exactly as provided by the email service
  - Verify SMTP_SERVER and SMTP_PORT are correct

### "Connection timed out"
- **Problem**: Can't reach SMTP server
- **Solution**:
  - Verify SMTP_SERVER and SMTP_PORT are correct
  - Check your firewall/network allows SMTP connections
  - For port 587: ensure TLS is enabled
  - Try port 465 (SSL) instead: set SMTP_PORT=465

### "Email sent successfully" but recipient didn't receive it
- **Problem**: Email was sent but went to spam or bounced
- **Solution**:
  - Check spam folder
  - Verify recipient email address is correct
  - Check email service logs for bounces
  - Some services have rate limiting - wait a moment and retry

### "Timeout" error
- **Problem**: SMTP server took too long to respond
- **Solution**:
  - Check network connection
  - Try a different SMTP server
  - Increase timeout in code (currently 10 seconds)

## Security Best Practices

1. **Never commit `.env`** - it contains credentials
   - The `.env` file is in `.gitignore` - never remove it
   - Verify with: `git status` (should not show .env)

2. **Use app-specific passwords**
   - For Gmail: Use App Passwords, not your main password
   - For other services: Follow their security recommendations

3. **Limit file sizes**
   - Large attachments may exceed email server limits
   - Default limit: 500MB for web uploads
   - Email attachment limits vary by provider (Gmail: 25MB)

4. **Log sensitive information carefully**
   - Don't log SMTP credentials
   - Error messages are visible to users (be cautious)

5. **Use TLS/SSL**
   - Port 587: TLS (recommended)
   - Port 465: SSL
   - Never send credentials unencrypted

## Advanced Configuration

### Custom SMTP Timeouts
Edit `src/web/app.py` line 119:
```python
with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as server:
```

### Sending from Different Email
By default, the "Your Email" field is used as the sender. The actual email account comes from SMTP_USERNAME. To allow custom sender:
1. Some SMTP servers allow different "From" addresses
2. Gmail requires the email to be your account
3. Other services may have different restrictions

### HTML Email Body
To send formatted HTML emails instead of plain text, modify `send_encrypted_file_email()` in `src/web/app.py`:
```python
msg.attach(MIMEText(body, 'html'))  # Change 'plain' to 'html'
```

## Need Help?

If you encounter issues:

1. **Check error messages** - they often indicate the exact problem
2. **Test SMTP credentials** - ensure they work with your email client first
3. **Review logs** - application console shows detailed error information
4. **Check email service documentation** - SMTP settings vary by provider

## Disabling Email

To disable email sharing completely, delete the `.env` file or set empty SMTP credentials. The application will gracefully fall back to direct download.

---

For more information about the File Encryption Tool, see [README.md](README.md)
