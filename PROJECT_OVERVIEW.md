# Project Overview: SysCallGuardian — System Call Gateway

This document provides a comprehensive summary of the architecture, features, and technical milestones of the **SysCallGuardian** project. SysCallGuardian is a multi-layered security gateway designed to intercept, analyze, and govern system calls in real-time with strict Role-Based Access Control (RBAC).

---

## 🏗️ 1. System Architecture
SysCallGuardian is built with a modular, security-first approach, separating sensitive kernel-level interception logic from the administrative dashboard.

### 🔹 Backend (Python/Flask)
- **Modular Services**:
  - `auth_rbac`: Manages roles, permissions, and session security.
  - `syscall_layer`: Intercepts and processes system call requests.
  - `policy_engine`: Evaluates real-time rules for allowing/blocking activity.
  - `logging_detection`: Handles cryptographic audit logs and threat scoring.
- **Database**: SQLite persistence for users, session isolation, and immutable syscall logs.
- **Security Protocols**: Bcrypt password hashing, SHA-256 log chaining, and OTP-based verification.

### 🔹 Frontend (HTML5/Vanilla JS/Chart.js)
- **Unified SPA**: A reactive single-page application with role-tailored views.
- **Analytics Engine**: Native **Chart.js v4** integration for high-performance visualizations.
- **Aesthetics**: Premium dark-mode interface with glassmorphism, dynamic animations, and responsive layouts.

---

## 🛡️ 2. Role-Based Access Control (RBAC)
SysCallGuardian enforces the **Principle of Least Privilege**. Each role has a distinct accessibility profile tailored to its responsibilities.

### 👑 Admin (Security Officer)
Full oversight of system health and security integrity.
- **Dashboard**: Global real-time stats for *all* users and roles.
- **Logs**: Access to every syscall recorded in the system.
- **Management**: The only role capable of creating/toggling policies and managing risk thresholds.
- **Integrity**: Permission to run SHA-256 chain verification for audit compliance.

### ⚙️ Developer (Operational User)
Power users who need to run applications and debug activity.
- **Dashboard**: Personal view showing their specific performance and syscall counts.
- **Logs**: Can view general system activity for debugging, but sensitive paths (e.g., `/etc/shadow`, root directories) are automatically **redacted**.
- **Policies**: Read-only preview of active policies (helps in understanding why a script might be getting blocked).

### 👤 Guest (Restricted User)
Minimal footprint for external or trial accounts.
- **Personal View**: A simplified dashboard showing only their own metrics (Allowed/Blocked counts).
- **Restrictions**: Strictly limited to `file_read` and `dir_list`. No permission to execute processes or write to files.
- **Privacy**: Cannot see other users' usernames, risk scores, or global traffic heatmaps.

---

## 🔐 3. Authentication & Recovery Flow
The authentication system is designed to be both secure and user-friendly, with specific recovery paths for different roles.

- **Strict Tab-Based Identity**: The login and recovery modals strictly respect the selected role tab (Admin, Dev, or Guest) to prevent role-spoofing during password reset.
- **Guest Recovery**: Self-service via **Email OTP**. Guests can reset their passwords by verifying a 6-digit code sent to their registered email.
- **Admin/Dev Recovery**: Strategic restriction. These roles must trigger a "Reset Request" that requires administrative approval, preventing automated takeovers of high-privilege accounts.
- **Login Flexibility**: Supports authentication via both **Username** and **Email Address**.

---

## 📋 4. Core User Personas
For testing and demonstration, the following accounts are pre-seeded in the system:

| Role | Username | Password | Purpose |
| :--- | :--- | :--- | :--- |
| **Admin** | `Tejax` | `U@itej99x` | Security oversight & Policy management |
| **Admin** | `Akael` | `Akhil9890` | Secondary security administrator |
| **Developer** | `Vancika` | `Van112358` | Application development & Debugging |
| **Guest** | *Any Email* | *Custom* | Restricted trial access |

---

## 🧪 5. Advanced Security Implementations

### ⛓️ SHA-256 Log Integrity Chain
Every entry in the `syscall_logs` table is cryptographically linked to the previous one. If a single row is modified or deleted by an attacker, the entire chain "breaks," and the Admin is alerted during the next integrity check.

### 🕵️ Real-time Threat Detection
- **Risk Scoring**: Users start at 0. Every "Blocked" syscall or attempt to access sensitive system files increases their `risk_score`.
- **Flagging**: Users exceeding a threshold (e.g., 70+) are automatically flagged in the UI for immediate investigation.
- **Path Sanitization**: For non-admin roles, any syscall involving system-critical paths is redacted in the logs to prevent information leakage.

---

## 🚀 6. Project Roadmap

| Phase | Milestone | Focus | Status |
| :--- | :--- | :--- | :--- |
| **1.0** | Interception Layer | Core syscall logic | ✅ Done |
| **2.0** | SQLite & Auth | RBAC Foundation | ✅ Done |
| **3.0** | Analytics 1.0 | External Dash integration | ✅ Done |
| **3.5** | Unified UI | Chart.js & SPA Migration | ✅ Done |
| **4.0** | RBAC Maturity | Role-tailored dashboards & OTP | ✅ Done |
| **5.0** | Advanced Policies | Rule-set export/import | 📝 Planned |

---
*Last Updated: 2026-04-04 · SysCallGuardian Engineering Team*

