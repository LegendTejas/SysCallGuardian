# 📡 API Documentation
**Project:** SysCallGuardian — Secure System Call Gateway with RBAC & Real-Time Monitoring
**Version:** 1.0 · Phase 4 Complete

---

## Base URL
```
http://localhost:5000
```

All protected routes require:
```
Authorization: Bearer <token>
```

---

## 🔐 Authentication APIs

### 1. Register User
**POST** `/api/auth/register`

**Request Body:**
```json
{
  "username": "tejas",
  "password": "AdminPass1",
  "role": "admin"
}
```

**Response `201`:**
```json
{
  "message": "User 'tejas' registered with role 'admin'."
}
```

**Errors:**
- `400` — Missing fields or weak password
- `409` — Username already exists

---

### 2. Login
**POST** `/api/auth/login`

**Request Body:**
```json
{
  "username": "tejas",
  "password": "AdminPass1"
}
```

**Response `200`:**
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "role": "admin",
  "username": "tejas"
}
```

**Errors:**
- `400` — Missing fields
- `401` — Invalid credentials (also increments risk_score)

---

### 3. Logout
**POST** `/api/auth/logout`

**Headers:**
```
Authorization: Bearer <token>
```

**Response `200`:**
```json
{
  "message": "Logged out successfully."
}
```

> Token is immediately invalidated in the sessions table. Any subsequent request with this token returns 401.

---

## 👤 User & Role APIs

### 4. Get Current User
**GET** `/api/user/me`

**Headers:**
```
Authorization: Bearer <token>
```

**Response `200`:**
```json
{
  "username": "tejas",
  "role": "admin",
  "is_flagged": false,
  "risk_score": 0.0
}
```

---

### 5. Get All Users
**GET** `/api/users`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role. Returns all users with real syscall statistics.

**Response `200`:**
```json
[
  {
    "id": 1,
    "username": "tejas",
    "role": "admin",
    "is_flagged": 0,
    "risk_score": 0.0,
    "created_at": "2026-04-01T10:00:00",
    "total_calls": 4102,
    "blocked_calls": 0
  },
  {
    "id": 3,
    "username": "guest1",
    "role": "guest",
    "is_flagged": 1,
    "risk_score": 87.0,
    "created_at": "2026-04-01T11:00:00",
    "total_calls": 97,
    "blocked_calls": 42
  }
]
```

---

### 6. Change User Role
**PUT** `/api/users/:id/role`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role. Admin cannot change their own role.

**Request Body:**
```json
{
  "role": "developer"
}
```

**Response `200`:**
```json
{
  "message": "Role updated to 'developer' for user 'guest1'.",
  "user_id": 3,
  "new_role": "developer"
}
```

**Errors:**
- `400` — Invalid role value
- `400` — Cannot change your own role
- `404` — User not found

---

### 7. Revoke User Session
**POST** `/api/users/:id/revoke`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role. Deletes all active sessions for the user — forces re-login.

**Response `200`:**
```json
{
  "message": "Revoked 1 session(s).",
  "sessions_revoked": 1
}
```

---

### 8. Clear User Flag
**POST** `/api/users/:id/unflag`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role. Resets `is_flagged = 0` and `risk_score = 0.0`.

**Response `200`:**
```json
{
  "message": "User 'guest1' cleared — flag and risk score reset.",
  "user_id": 3
}
```

**Errors:**
- `404` — User not found

---

### 9. Get All Roles
**GET** `/api/user/roles`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role.

**Response `200`:**
```json
{
  "admin":     ["file_read","file_write","file_delete","dir_list","exec_process","system_dir_access","view_logs","manage_policies","view_dashboard"],
  "developer": ["file_read","file_write","dir_list","exec_process","view_logs","view_dashboard"],
  "guest":     ["file_read","dir_list"]
}
```

---

## 🛡️ Policy APIs

### 10. Get All Policies
**GET** `/api/policies`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role. Returns all policies (active and inactive).

**Response `200`:**
```json
[
  {
    "id": 1,
    "name": "block_guest_exec",
    "rule_json": {
      "action": "exec_process",
      "allow_roles": ["admin", "developer"],
      "deny_roles": ["guest"]
    },
    "is_active": true,
    "updated_at": "2026-04-01T10:00:00"
  }
]
```

---

### 11. Create Policy
**POST** `/api/policies`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role.

**Request Body:**
```json
{
  "name": "block_guest_write",
  "rule_json": {
    "action": "file_write",
    "allow_roles": ["admin", "developer"],
    "deny_roles": ["guest"],
    "conditions": {
      "max_risk_score": 60
    }
  }
}
```

**Response `201`:**
```json
{
  "message": "Policy created successfully.",
  "id": 6
}
```

**Errors:**
- `400` — Missing name or rule_json, invalid action, unknown roles, role conflict
- `409` — Policy name already exists

---

### 12. Update Policy
**PUT** `/api/policies/:id`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role. Provide at least one of `rule_json` or `is_active`.

**Request Body:**
```json
{
  "rule_json": {
    "action": "file_write",
    "allow_roles": ["admin"]
  },
  "is_active": true
}
```

**Response `200`:**
```json
{
  "message": "Policy updated."
}
```

**Errors:**
- `400` — No fields provided, invalid rule
- `404` — Policy not found

---

## ⚙️ System Call APIs

> 🔒 All syscall routes require `Authorization: Bearer <token>`.
> RBAC and policy checks are enforced before any execution.

### 13. Read File
**POST** `/api/syscall/read`

**Request Body:**
```json
{
  "file_path": "test.txt"
}
```

**Response `200` (allowed):**
```json
{
  "status": "allowed",
  "content": "File content here"
}
```

**Response `403` (blocked):**
```json
{
  "status": "blocked",
  "reason": "Role 'guest' lacks permission 'file_read'."
}
```

---

### 14. Write File
**POST** `/api/syscall/write`

**Request Body:**
```json
{
  "file_path": "test.txt",
  "data": "Hello World"
}
```

**Response `200`:**
```json
{
  "status": "allowed",
  "message": "Write successful"
}
```

---

### 15. Delete File
**POST** `/api/syscall/delete`

**Request Body:**
```json
{
  "file_path": "test.txt"
}
```

**Response `403` (guest/developer blocked):**
```json
{
  "status": "blocked",
  "reason": "Role 'developer' is not permitted for 'file_delete' (policy: 'block_guest_delete')."
}
```

---

### 16. Execute Process
**POST** `/api/syscall/execute`

**Request Body:**
```json
{
  "command": "ls -la"
}
```

**Response `200`:**
```json
{
  "status": "allowed",
  "output": "total 12\ndrwxr-xr-x ...",
  "return_code": 0
}
```

**Response `403` (blocked command):**
```json
{
  "status": "blocked",
  "reason": "Command 'rm' is not in the allowed command list."
}
```

> Allowed commands: `ls`, `pwd`, `whoami`, `echo`, `cat`, `head`, `tail`, `python3`, `python`, `node`, `java`, `grep`, `find`, `mkdir`, `touch`, `cp`, `mv`, `wc`, `sort`, `uniq`

---

## 📜 Logging APIs

### 17. Get Logs
**GET** `/api/logs`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `developer` role or higher.

**Query Parameters (all optional):**

| Param | Type | Description |
|---|---|---|
| `user` | string | Filter by username |
| `status` | string | `allowed` / `blocked` / `flagged` |
| `call_type` | string | `file_read` / `file_write` / `exec_process` / etc. |
| `date` | string | `2026-03-25` |
| `from` | string | `2026-03-25T00:00:00` |
| `to` | string | `2026-03-25T23:59:59` |
| `page` | integer | Page number (default: 1) |
| `per_page` | integer | Results per page (default: 20) |

**Response `200`:**
```json
{
  "page": 1,
  "total": 120,
  "logs": [
    {
      "id": 42,
      "user": "tejas",
      "call_type": "file_read",
      "target_path": "test.txt",
      "status": "allowed",
      "reason": null,
      "risk_delta": 0.0,
      "timestamp": "2026-03-25T10:00:00",
      "hash_preview": "a3f2c1d8e4b7…"
    }
  ]
}
```

---

### 18. Verify All Log Integrity
**GET** `/api/logs/verify`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role. Walks the full SHA-256 hash chain across all log entries.

**Response `200` (valid):**
```json
{
  "status": "valid",
  "message": "Logs are not tampered. Chain integrity verified.",
  "tampered_ids": []
}
```

**Response `200` (tampered):**
```json
{
  "status": "tampered",
  "message": "Tampering detected in 2 log entries.",
  "tampered_ids": [5, 12]
}
```

---

### 19. Verify Single Log Entry
**GET** `/api/logs/verify/:id`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role. Verifies the hash of one specific log entry.

**Response `200`:**
```json
{
  "log_id": 42,
  "valid": true,
  "tampered": false,
  "message": "Hash verified."
}
```

---

## 🚨 Threat Detection APIs

### 20. Get Suspicious Users
**GET** `/api/threats`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `admin` role. Returns users with `is_flagged = 1` or `risk_score >= 20`.

**Response `200`:**
```json
[
  {
    "user_id": 3,
    "username": "guest1",
    "role": "guest",
    "risk_score": 87.0,
    "risk_level": "critical"
  },
  {
    "user_id": 4,
    "username": "intern_k",
    "role": "guest",
    "risk_score": 28.0,
    "risk_level": "medium"
  }
]
```

**Risk Levels:**

| Score | Level |
|---|---|
| 0 – 19 | low |
| 20 – 39 | medium |
| 40 – 69 | high |
| 70 – 100 | critical |

---

## 📊 Dashboard APIs

### 21. System Statistics
**GET** `/api/dashboard/stats`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `developer` role or higher.

**Response `200`:**
```json
{
  "total_calls": 4821,
  "allowed": 4512,
  "blocked": 309,
  "flagged": 5,
  "suspicious_users": 3,
  "top_users": [
    { "username": "tejas", "call_count": 4102 },
    { "username": "dev1",  "call_count": 712  }
  ]
}
```

---

### 22. Activity Timeline
**GET** `/api/dashboard/activity`

**Headers:**
```
Authorization: Bearer <token>
```

> 🔒 Requires `developer` role or higher. Returns hourly data for the last 12 hours.

**Response `200`:**
```json
[
  { "hour": "10:00", "allowed": 210, "blocked": 12, "calls": 222 },
  { "hour": "11:00", "allowed": 318, "blocked": 22, "calls": 340 }
]
```

---

## 🔒 Security Notes

- All protected routes require a valid JWT in the `Authorization: Bearer` header
- RBAC enforced at middleware level — permission check happens before any business logic
- Policies evaluated dynamically at runtime — changes take effect immediately
- All system calls are validated, sanitized, logged, and checked against active policies
- SHA-256 hash chaining makes audit logs tamper-evident
- Risk score updated on every blocked or flagged call attempt
- Failed logins increment risk score by 10.0 per attempt; 5 failures triggers flag

---

## 📌 HTTP Status Codes

| Code | Meaning |
|---|---|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request — missing or invalid fields |
| 401 | Unauthorized — missing, invalid, or expired token |
| 403 | Forbidden — insufficient role or permission |
| 404 | Not Found |
| 409 | Conflict — duplicate resource |
| 500 | Internal Server Error |

---

## 🧠 Policy Rule Format Reference

```json
{
  "action":      "exec_process",
  "allow_roles": ["admin", "developer"],
  "deny_roles":  ["guest"],
  "conditions":  {
    "max_risk_score": 60,
    "time_range":     ["09:00", "18:00"]
  }
}
```

| Field | Required | Description |
|---|---|---|
| `action` | ✅ | Syscall type this rule governs |
| `allow_roles` | ❌ | Roles explicitly permitted |
| `deny_roles` | ❌ | Roles explicitly blocked (evaluated first) |
| `conditions.max_risk_score` | ❌ | Block if user's risk_score exceeds this |
| `conditions.time_range` | ❌ | Only allow within this UTC time window |

**Valid actions:** `file_read`, `file_write`, `file_delete`, `dir_list`, `exec_process`, `system_dir_access`

**Decision order:**
1. No matching active policy → **ALLOW** (default permissive)
2. Role in `deny_roles` → **DENY**
3. Role not in `allow_roles` → **DENY**
4. Condition fails → **DENY**
5. All checks pass → **ALLOW**

---

*SysCallGuardian API Documentation · v1.0 · Phase 4 Complete*
