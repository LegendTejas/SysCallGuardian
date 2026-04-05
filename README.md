# SysCallGuardian — Professional System Call Gateway

![Version](https://img.shields.io/badge/version-4.0.0--stable-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)

**SysCallGuardian** is a high-performance, security-focused system call gateway designed to monitor, filter, and audit system-level operations in real-time. It provides a centralized dashboard for administrators to enforce granular security policies across a multi-user environment.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.8 or higher
- SQLite3

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/your-repo/secure-syscall-gateway.git
cd secure-syscall-gateway

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt
```

### 3. Initialize Database
```bash
# Seed the database with core users and roles
python reseed_users.py
```

### 4. Run the Application
```bash
cd backend
python app.py
```
The gateway will be active at `http://127.0.0.1:5000`.

---

## 🔐 Core User Credentials (Test Accounts)

| Role | Username | Password |
| :--- | :--- | :--- |
| **Admin** | `Tejax` | `U@itej99x` |
| **Admin** | `Akael` | `Akhil9890` |
| **Developer** | `Vancika` | `Van112358` |
| **Guest** | *Your Email* | *OTP via Email* |

---

## ✨ Key Features
- **Real-time Syscall Interception**: Monitoring of `file_read`, `file_write`, `exec_process`, and more.
- **Dynamic RBAC**: Dedicated dashboards for Admins, Developers, and Guests with strict data isolation.
- **SHA-256 Audit Chain**: Cryptographically linked logs to detect and prevent unauthorized tampering.
- **OTP Recovery**: Secure password reset flow for Guest accounts.
- **Threat Intelligence**: Automated risk scoring and user flagging based on heuristic analysis.

---

## 📖 Documentation
For a deep dive into the architecture, security protocols, and development roadmap, please refer to the [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md).

---
*Developed by the SysCallGuardian Engineering Team*
