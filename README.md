# SysCallGuardian — Professional System Call Gateway

![Version](https://img.shields.io/badge/version-4.0.0--stable-blue)
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

| Role | Username | Password | Purpose |
| :--- | :--- | :--- | :--- |
| **Admin** | `Tejax` | `U@itej99x` | Security oversight & Policy management |
| **Developer** | `Vancika` | `Van112358` | Application development & Debugging |
| **Guest A** | `GuestA` | `Guest@123` | Restricted trial access (Read-only) |
| **Guest B** | `GuestB` | `Guest@456` | Restricted trial access (Read-only) |

---

## ✨ Key Features
- **Real-time Syscall Interception**: Monitoring of `file_read`, `file_write`, `exec_process`, and more.
- **Dynamic RBAC**: Dedicated dashboards for Admins, Developers, and Guests with strict data isolation.
- **Managed Registration**: Public self-registration is disabled. New users must be registered by an **Admin** or **Developer** directly via the secure dashboard.
- **SHA-256 Audit Chain**: Cryptographically linked logs to detect and prevent unauthorized tampering.
- **Forgot Password**: Secure password reset flow remains active for all users via Email OTP.
- **Threat Intelligence**: Automated risk scoring and user flagging based on heuristic analysis.
- **CRT Terminal UI**: Modern, premium dashboard with a CRT scanline aesthetic and status-aware log coloring.

---

## 📖 Documentation
For a deep dive into the architecture, security protocols, and development roadmap, please refer to the [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md).

---
*Developed by the SysCallGuardian Engineering Team*
