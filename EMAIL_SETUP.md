# Email Configuration Guide (Admin Only)

This guide is for **server administrators** who want to enable email sharing for users.

## Overview

The web interface includes email sharing - users can send encrypted files to recipients. The system uses a **single server-side email account** to send all emails on behalf of users.

**Users don't need to configure anything** - they just enter sender and receiver email addresses in the web interface.

## How It Works

1. **Admin (you)**: Configure one email account in `.env` (one time setup)
2. **Users**: Enter their email as "sender" and recipient email in the web form
3. **System**: Sends email from the configured account, but shows user emails in headers
4. **Recipient**: Receives email showing the user as the sender

```
User provides:
  Sender: alice@company.com
  Receiver: bob@company.com

System sends:
  From: alice@company.com
  To: bob@company.com
  Via: noreply@yourserver.com (configured in .env)

Recipient sees: Email from alice@company.com with encrypted file attached
```

## Quick Start (3 Steps)

### Step 1: Copy Configuration Template
```bash
cp .env.example .env
```

### Step 2: Get Gmail App Password (if using Gmail)
1. Go to https://myaccount.google.com/apppasswords
2. If prompted, enable 2-Step Verification first
3. Select "Mail" and "Windows Computer" (or your platform)
4. Google generates a 16-character app password
5. Copy this password

### Step 3: Edit `.env` File
```bash
# Edit .env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=xxxx xxxx xxxx xxxx  # Your 16-character app password
```

### Step 4: Install & Test
```bash
# Install python-dotenv if not already installed
pip install -r requirements.txt

# Start the server
python3 web_main.py
```

## Email Provider Setup

### Gmail (Recommended)

**Requirements:**
- Gmail account
- 2-Factor Authentication enabled

**Steps:**

1. **Enable 2-Factor Authentication:**
   - Go to https://myaccount.google.com/security
   - Click "2-Step Verification"
   - Follow the setup process

2. **Generate App Password:**
   - Go to https://myaccount.google.com/apppasswords
   - You should see "App passwords" option
   - Select "Mail" as the app
   - Select "Windows Computer" (or your device)
   - Google generates a 16-character password
   - Copy it

3. **Configure .env:**
   ```
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your-email@gmail.com
   SMTP_PASSWORD=xxxx xxxx xxxx xxxx
   ```

### Outlook

```bash
SMTP_SERVER=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_USERNAME=your-email@outlook.com
SMTP_PASSWORD=your-password
```

### SendGrid

```bash
SMTP_SERVER=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=SG.your-sendgrid-api-key
```

### AWS SES

```bash
SMTP_SERVER=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USERNAME=your-ses-username
SMTP_PASSWORD=your-ses-password
```

## Testing Email Configuration

### Manual Test

Edit `.env` and add temporary logging, then run:
```bash
python3 web_main.py
```

Go to the web interface at http://127.0.0.1:8000:
1. Select a file to encrypt
2. Choose your encryption algorithm
3. Enter your email as "Your Email"
4. Enter a test recipient email as "Recipient Email"
5. Click "Encrypt and Send via Email"
6. Check the recipient's email for the encrypted file

### Test Script

```python
import os
import sys
from src.web.app import send_encrypted_file_email

# Create a test file
test_file = "/tmp/test.enc"
with open(test_file, 'wb') as f:
    f.write(b"test encrypted content")

# Test sending
success, message = send_encrypted_file_email(
    sender_email="sender@example.com",
    receiver_email="recipient@example.com",
    encrypted_file_path=test_file,
    original_filename="test.txt",
    access_code="ABC123XYZ"
)

print(f"Success: {success}")
print(f"Message: {message}")
```

## Troubleshooting

### "Email sending not configured on this server"

**Problem:** SMTP credentials not set in `.env`

**Solution:**
1. Verify `.env` file exists in project root
2. Check that SMTP_USERNAME and SMTP_PASSWORD are filled
3. Restart the server after editing `.env`

### "Email service authentication failed"

**Problem:** Wrong SMTP credentials

**Solution:**
- For Gmail:
  - Verify you're using an **App Password**, not your regular password
  - App passwords are 16 characters with spaces
  - Requires 2-factor authentication
- For other services:
  - Verify username and password are correct
  - Check with your email provider for correct SMTP settings

### "Email service error: Connection timed out"

**Problem:** Can't reach SMTP server

**Solution:**
1. Verify SMTP_SERVER and SMTP_PORT are correct for your provider
2. Check firewall/network allows outgoing SMTP (port 587 or 465)
3. Try port 465 (SSL) instead of 587 (TLS)

### Email sent but recipient didn't receive it

**Problem:** Email bounced or went to spam

**Solutions:**
- Check recipient's spam folder
- Verify recipient email address is correct
- Check email service logs for bounce messages
- Some services have rate limiting - wait and retry

### Recipients see "From: noreply@..." instead of user's email

**Note:** Some email providers (Gmail) override the "From" field with the actual SMTP account. This is normal for security reasons. Recipients can still reply, and it goes to the user's email (via Reply-To header).

To mitigate this, consider using:
- SendGrid or Mailgun with domain authentication
- AWS SES with verified sender domains
- Custom domain with DKIM/SPF records

## User Instructions

**Tell users:**

> Users don't need to configure anything! Just enter:
> 1. Your email address in "Your Email" field
> 2. Recipient's email in "Recipient Email" field
> 3. Select file and encryption algorithm
> 4. Click "Encrypt and Send via Email"
>
> The encrypted file will be sent automatically!

## Security Considerations

### For Administrators

1. **Keep .env Secure**
   - Never commit .env to git (already in .gitignore)
   - Restrict file permissions: `chmod 600 .env`
   - Only deploy on secure servers

2. **Use App Passwords (Gmail)**
   - App passwords are safer than main passwords
   - Can be revoked individually
   - Don't grant access to your entire account

3. **Monitor Email Usage**
   - Most email providers have sending limits
   - Gmail: 500 emails/day for free account
   - SendGrid, Mailgun: Paid tiers with higher limits
   - Monitor to prevent abuse

4. **File Attachment Size**
   - Web uploads limited to 500MB
   - Email attachment limits vary by provider
   - Gmail: 25MB limit
   - Outlook: 20MB limit
   - SendGrid: 30MB limit

### For Users

- Never share decryption keys via email
- Sender should provide key through separate, secure channel
- Only share encrypted files with intended recipients

## Advanced Configuration

### Rate Limiting

If you have many users, consider adding rate limiting:

```python
# In src/web/app.py, add before sending:
time.sleep(1)  # 1 second delay between emails
```

### Logging Email Activity

Add logging to track sent emails:

```python
# In send_encrypted_file_email function, add:
import logging
logger = logging.getLogger(__name__)

# After successful send:
logger.info(f"Email sent from {sender_email} to {receiver_email}")
```

### Custom Email Domain

For better delivery rates, set up a custom domain:

1. Use SendGrid or Mailgun (easier than Gmail)
2. Verify your domain with DKIM/SPF records
3. Update SMTP_SERVER and SMTP_USERNAME in .env
4. Sender emails will appear as "from your-domain.com"

## Disabling Email

To temporarily disable email sending:

1. Delete the `.env` file, OR
2. Set SMTP_USERNAME or SMTP_PASSWORD to empty in `.env`

Users will see: "Email sending not configured on this server"

## Need Help?

1. **Check error messages** - they indicate the specific problem
2. **Review logs** - application console shows detailed errors
3. **Test with a simple email** - use the test script above
4. **Check email provider docs** - SMTP settings vary

## File Attachment Size Note

```
User's file: 10 MB
System encrypts it: ~10 MB (encryption adds minimal overhead)
Email attachment: ~10 MB (base64 encoded, ~33% larger)
Email provider limit: 25-30 MB (Gmail 25MB, Outlook 20MB, SendGrid 30MB)
```

For large files (>20MB), warn users or implement file compression.

---

**For email provider documentation:**
- Gmail: https://support.google.com/accounts/answer/185833
- Outlook: https://support.microsoft.com/en-us/office/pop-imap-and-smtp-settings
- SendGrid: https://sendgrid.com/docs/for-developers/sending-email/
- AWS SES: https://docs.aws.amazon.com/ses/latest/dg/

For more information, see [README.md](README.md)
