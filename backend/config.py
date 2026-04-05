"""
config.py
Central config — all modules import constants from here.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# Flask
SECRET_KEY  = os.getenv("SECRET_KEY", "dev_secret_change_in_prod")
DEBUG       = os.getenv("DEBUG", "true").lower() == "true"
PORT        = int(os.getenv("PORT", 5000))

# JWT
JWT_SECRET     = os.getenv("JWT_SECRET", "jwt_secret_change_in_prod")
JWT_ALGORITHM  = "HS256"
TOKEN_EXPIRY_H = int(os.getenv("TOKEN_EXPIRY_H", 4))

# DB — switches to in-memory SQLite during tests
TESTING = os.getenv("TESTING", "false").lower() == "true"
DB_PATH = ":memory:" if TESTING else os.getenv("DB_PATH", "syscall_gateway.db")

# SMTP setup (for email notifications)
SMTP_SERVER   = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

# Security thresholds
MAX_FAILED_LOGINS_BEFORE_FLAG = 5
RISK_INCREMENT_PER_FAIL       = 10.0
MAX_RISK_SCORE                = 100.0
