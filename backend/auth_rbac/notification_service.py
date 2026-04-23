"""
auth_rbac/notification_service.py
Handles sending emails for password recovery and alerts using smtplib.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import config

def send_email(to_email: str, subject: str, html_body: str) -> bool:
    """
    Sends an email using the SMTP settings configured in backend/.env
    If SMTP_USERNAME is empty, it simulates sending by printing to console.
    """
    if not config.SMTP_USERNAME or config.SMTP_USERNAME == "your_gmail@gmail.com":
        print("=" * 60)
        print(f"[SIMULATED EMAIL TO] {to_email}")
        print(f"[SUBJECT] {subject}")
        print("-" * 60)
        print(html_body)
        print("=" * 60)
        print("NOTE: Real email not sent because SMTP credentials are not configured in .env")
        return True

    try:
        msg = MIMEMultipart()
        msg["From"] = config.SMTP_USERNAME
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(html_body, "html"))

        server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT)
        server.starttls()
        server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
        server.sendmail(config.SMTP_USERNAME, to_email, msg.as_string())
        server.quit()
        print(f"[EMAIL SENT] Successfully sent email to {to_email}")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send email to {to_email}: {e}")
        return False

def send_guest_otp(to_email: str, otp_code: str):
    subject = "Your SysCallGuardian OTP"
    body = f"""
    <html>
      <body style="font-family: sans-serif; color: #1A1916;">
        <h2>SysCallGuardian Recovery</h2>
        <p>You requested a one-time password to recover your account.</p>
        <div style="background: #F2F1ED; padding: 16px; font-size: 24px; font-family: monospace; font-weight: bold; text-align: center; border-radius: 8px;">
            {otp_code}
        </div>
        <p>If you did not request this, please ignore this email.</p>
      </body>
    </html>
    """
    return send_email(to_email, subject, body)

def send_developer_secure_link(to_email: str, reset_token: str):
    subject = "SysCallGuardian Developer Reset Link"
    link = f"http://localhost:5000/reset-password?token={reset_token}"
    body = f"""
    <html>
      <body style="font-family: sans-serif; color: #1A1916;">
        <h2>Developer Account Reset</h2>
        <p>A secure reset link has been generated. <b>TOTP will be required</b> to complete this action.</p>
        <p><a href="{link}" style="background: #0F2D1F; color: white; padding: 10px 16px; text-decoration: none; border-radius: 6px; display: inline-block;">Secure Reset Link</a></p>
        <p>Or copy this link: {link}</p>
      </body>
    </html>
    """
    return send_email(to_email, subject, body)

def send_admin_alert(to_email: str, admin_username: str, admin_email: str):
    subject = "[URGENT] SysCallGuardian Admin Reset Requested"
    body = f"""
    <html>
      <body style="font-family: sans-serif; color: #1A1916;">
        <h2 style="color: #C0392B;">Admin Recovery Initiated</h2>
        <p>A password reset was requested for the admin account: <b>{admin_username}</b> (Email: {admin_email}).</p>
        <p>Our security team has been notified. If this is legitimate, please await authorization. If you did not request this, action is required immediately.</p>
      </body>
    </html>
    """
    return send_email(to_email, subject, body)

def send_security_broadcast(to_emails: list, admin_user: str):
    """Simple broadcast to designated emails"""
    subject = "[CRITICAL] SysCallGuardian Security Alert"
    body = f"""
    <html>
      <body style="font-family: sans-serif; color: #1A1916;">
        <h2 style="color: #C0392B;">Critical Broadcast Alert</h2>
        <p>An administrator (<b>{admin_user}</b>) has issued a system-wide security alert.</p>
        <p>Please review current system activity and threat logs immediately.</p>
        <hr style="border:none; border-top:1px solid #eee; margin: 20px 0;">
        <p style="font-size:12px; color:#666;">This is an automated security notification from SysCallGuardian.</p>
      </body>
    </html>
    """
    success = True
    for email in to_emails:
        if not send_email(email, subject, body):
            success = False
    return success
