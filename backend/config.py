"""
config.py
Central config — all modules import constants from here.
Values are read from .env via python-dotenv.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# Flask
SECRET_KEY   = os.getenv("SECRET_KEY", "dev_secret_change_in_prod")
DEBUG        = os.getenv("DEBUG", "true").lower() == "true"
PORT         = int(os.getenv("PORT", 5000))

# JWT
JWT_SECRET      = os.getenv("JWT_SECRET", "jwt_secret_change_in_prod")
JWT_ALGORITHM   = "HS256"
TOKEN_EXPIRY_H  = int(os.getenv("TOKEN_EXPIRY_H", 8))

# Security
MAX_FAILED_LOGINS_BEFORE_FLAG = 5
RISK_INCREMENT_PER_FAIL       = 10.0
MAX_RISK_SCORE                = 100.0

# DB
DB_PATH = os.getenv("DB_PATH", "syscall_gateway.db")