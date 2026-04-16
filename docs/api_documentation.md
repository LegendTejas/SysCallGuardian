# SysCallGuardian — Complete API Documentation v1.0

**Base URL:** `http://localhost:5000`  
**Content-Type:** All requests and responses use `application/json`  
**Authentication:** Bearer token via `Authorization: Bearer <token>` header

---

## Table of Contents

1. [Authentication](#1-authentication)
   - [POST /api/auth/login](#post-apiauthlogin)
   - [POST /api/auth/logout](#post-apiauthlogout)
   - [POST /api/auth/register](#post-apiauthregister)
   - [POST /api/auth/recover-info](#post-apiauthrecover-info)
   - [POST /api/auth/forgot-password](#post-apiauthforgot-password)
   - [POST /api/auth/reset-password](#post-apiauthreset-password)

2. [User Profile](#2-user-profile)
   - [GET /api/user/me](#get-apiuserme)
   - [GET /api/user/roles](#get-apiuserroles)

3. [User Management (Admin/Developer)](#3-user-management)
   - [GET /api/users](#get-apiusers)
   - [POST /api/users/:id/revoke](#post-apiusersidrevoke)
   - [POST /api/users/:id/unflag](#post-apiusersidunflag)
   - [PUT /api/users/:id/role](#put-apiusersidrole)
   - [DELETE /api/users/:id](#delete-apiusersid)

4. [Policy Management](#4-policy-management)
   - [GET /api/policies](#get-apipolicies)
   - [GET /api/policies/preview](#get-apipoliciespreview)
   - [POST /api/policies](#post-apipolicies)
   - [PUT /api/policies/:id](#put-apipoliciesid)
   - [DELETE /api/policies/:id](#delete-apipoliciesid)
   - [GET /api/policies/export](#get-apipoliciesexport)
   - [POST /api/policies/import](#post-apipoliciesimport)

5. [Syscall Gateway](#5-syscall-gateway)
   - [POST /api/syscall/read](#post-apisyscallread)
   - [POST /api/syscall/write](#post-apisyscallwrite)
   - [POST /api/syscall/delete](#post-apisyscalldelete)
   - [POST /api/syscall/dir_list](#post-apisyscalldir_list)
   - [GET /api/syscall/explorer](#get-apisyscallexplorer)
   - [POST /api/syscall/execute](#post-apisyscallexecute)
   - [GET/POST /api/syscall/system_info](#getpost-apisyscallsystem_info)

6. [Forensic Audit Logs](#6-forensic-audit-logs)
   - [GET /api/logs](#get-apilogs)
   - [GET /api/logs/verify](#get-apilogsverify)
   - [GET /api/logs/verify/:id](#get-apilogsverifyid)

7. [Threat Intelligence](#7-threat-intelligence)
   - [GET /api/threats](#get-apithreats)
   - [GET /api/threats/events](#get-apithreatsevents)

8. [Dashboard Analytics](#8-dashboard-analytics)
   - [GET /api/dashboard/stats](#get-apidashboardstats)
   - [GET /api/dashboard/activity](#get-apidashboardactivity)
   - [GET /api/dashboard/extended](#get-apidashboardextended)

---

## Authentication

All protected endpoints require the `Authorization` header:

```
Authorization: Bearer <token>
```

The token is a plain-text SHA-256 UUID-style string generated at login and stored in the `sessions` table. Tokens don't expire automatically — they are invalidated on logout or by an admin revoking sessions.

### RBAC Role Hierarchy

| Role | Level | Capabilities |
|------|-------|--------------|
| `guest` | 1 | Read own logs, run read syscalls |
| `developer` | 2 | All guest + manage users (limited), view policies, write syscalls |
| `admin` | 3 | Full access — delete users, manage policies, verify log chain |

`@require_role("X")` means the requesting user must be at role level **≥ X**.

---

## 1. Authentication

### `POST /api/auth/login`

Authenticates a user by username or email and issues a session token.

**Auth Required:** No

**Request Body:**
```json
{
  "username": "Tejax",
  "password": "U@itej99x"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | ✅ | Username **or** email address (case-insensitive) |
| `password` | string | ✅ | Plain-text password |

**Success Response — `200 OK`:**
```json
{
  "message": "Login successful",
  "token": "a3f9c1d2e5b84720a1c9f3e2d67b4a90",
  "role": "admin",
  "username": "Tejax"
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `400` | Missing username or password | `{ "error": "username and password are required." }` |
| `401` | Wrong credentials | `{ "error": "Invalid credentials." }` |

**Side Effects:**
- On wrong password: increments the user's `risk_score` by `RISK_INCREMENT_PER_FAIL` (configured in `config.py`)
- If `risk_score` crosses `MAX_FAILED_LOGINS_BEFORE_FLAG * RISK_INCREMENT_PER_FAIL`, the user's `is_flagged` is set to `1`
- On success: creates a row in the `sessions` table linking the token to the user ID

---

### `POST /api/auth/logout`

Invalidates the current session token by deleting it from the `sessions` table.

**Auth Required:** Yes (any role)

**Request Body:** None required

**Success Response — `200 OK`:**
```json
{
  "message": "Logged out successfully."
}
```

**Side Effects:** The token in the `Authorization` header is deleted from `sessions`. Any subsequent request using this token will return `401`.

---

### `POST /api/auth/register`

Creates a new user account. Role hierarchy is enforced: Developers can only create Guest accounts; Admins can create any role.

**Auth Required:** Yes  
**Minimum Role:** `developer`

**Request Body:**
```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "Str0ng!P@ssword",
  "role": "guest"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | ✅ | Must be unique |
| `password` | string | ✅ | Must pass strength validation (uppercase, lowercase, digit, special char) |
| `email` | string | ❌ | Optional, used for password recovery |
| `role` | string | ❌ | `guest` (default), `developer`, or `admin` |

**Password Strength Rules (enforced by `is_strong_password`):**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

**Success Response — `201 Created`:**
```json
{
  "message": "User 'newuser' registered with role 'guest'."
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `400` | Missing username or password | `{ "error": "username and password are required." }` |
| `400` | Weak password | `{ "error": "<strength validation message>" }` |
| `403` | Developer trying to create non-Guest role | `{ "error": "Forbidden.", "detail": "Developers can only create Guest accounts." }` |
| `409` | Username already exists | `{ "error": "Username already exists." }` |

---

### `POST /api/auth/recover-info`

Looks up a user's role by username or email. Used to pre-select the correct role tab on the login screen. Prevents user enumeration by returning `"role": "guest"` for unknown identities.

**Auth Required:** No

**Request Body:**
```json
{
  "identity": "Tejax"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identity` | string | ✅ | Username or email (case-insensitive) |

**Success Response — `200 OK`:**
```json
{
  "role": "admin"
}
```

> **Security Note:** If the identity is not found, the API still returns `200` with `"role": "guest"` rather than a `404`, preventing attackers from enumerating valid usernames.

---

### `POST /api/auth/forgot-password`

Initiates the role-aware password recovery flow. Behaviour differs by role:
- **Admin:** Sends a security alert email (only to the registered admin email)
- **Developer:** Sends a one-time secure reset link
- **Guest:** Sends a 6-digit OTP to their email (valid 15 minutes); also sends OTP to unregistered emails if they provide an email address directly

**Auth Required:** No

**Request Body:**
```json
{
  "identity": "Tejax"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identity` | string | ✅ | Username or email address |

**Success Response — `200 OK` (always):**
```json
{
  "message": "If an account matching those details exists, recovery instructions have been sent."
}
```

> **Security Note:** Always returns `200` regardless of whether the user was found. This prevents user enumeration attacks. The OTP is stored in the `otps` table with a 15-minute expiry.

**Side Effects:**
- For Guest accounts: inserts a row into `otps (email, otp_code, expires_at)`
- Sends an email via `notification_service` (SMTP)

---

### `POST /api/auth/reset-password`

Validates an OTP and resets the user's password. Enforces strong password rules. Deletes the OTP from the database after successful use to prevent reuse.

**Auth Required:** No

**Request Body:**
```json
{
  "identity": "Tejax",
  "otp": "847291",
  "new_password": "NewStr0ng!Pass"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identity` | string | ✅ | Username or email used to initiate recovery |
| `otp` | string | ✅ | 6-digit OTP code received by email |
| `new_password` | string | ✅ | New password (must pass strength validation) |

**Success Response — `200 OK`:**
```json
{
  "message": "Password successfully reset."
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `400` | Missing any field | `{ "error": "Missing parameters." }` |
| `400` | Weak new password | `{ "error": "<strength validation message>" }` |
| `400` | Invalid/expired OTP | `{ "error": "Invalid or expired verification code." }` |

**Side Effects:**
- Deletes the used OTP row from `otps` to prevent reuse
- Updates `users.password_hash` with the bcrypt hash of the new password

---

## 2. User Profile

### `GET /api/user/me`

Returns the authenticated user's own profile data including their current risk score and flag status.

**Auth Required:** Yes (any role)

**Request Body:** None

**Success Response — `200 OK`:**
```json
{
  "username": "Tejax",
  "role": "admin",
  "is_flagged": false,
  "risk_score": 15.5
}
```

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | The user's display name |
| `role` | string | Current RBAC role |
| `is_flagged` | boolean | Whether the threat engine has flagged this account |
| `risk_score` | float | Current cumulative risk score (0.0 – 100.0) |

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `401` | No/invalid token | `{ "error": "Unauthorized." }` |
| `404` | User deleted mid-session | `{ "error": "User not found." }` |

---

### `GET /api/user/roles`

Returns the list of all valid RBAC roles and their associated permission sets.

**Auth Required:** Yes  
**Minimum Role:** `developer`

**Request Body:** None

**Success Response — `200 OK`:**
```json
{
  "admin": ["file_read", "file_write", "file_delete", "dir_list", "exec_process", "system_info"],
  "developer": ["file_read", "file_write", "dir_list", "system_info"],
  "guest": ["file_read", "system_info"]
}
```

---

## 3. User Management

### `GET /api/users`

Returns all registered users with their real-time syscall statistics (total calls, blocked calls, risk score, flag status).

**Auth Required:** Yes  
**Minimum Role:** `developer`

**Request Body:** None

**Success Response — `200 OK`:**
```json
[
  {
    "id": 1,
    "username": "Tejax",
    "role": "admin",
    "is_flagged": 0,
    "risk_score": 0.0,
    "created_at": "2026-04-01T10:00:00",
    "total_calls": 56,
    "blocked_calls": 2
  },
  {
    "id": 2,
    "username": "Vancika",
    "role": "developer",
    "is_flagged": 1,
    "risk_score": 45.0,
    "created_at": "2026-04-02T12:30:00",
    "total_calls": 26,
    "blocked_calls": 3
  }
]
```

Results are ordered by `total_calls DESC`. Users with no syscall history still appear (via `LEFT JOIN`).

---

### `POST /api/users/:id/revoke`

Force-revokes all active sessions for a specific user, requiring them to log in again. Does not delete the user account.

**Auth Required:** Yes  
**Minimum Role:** `developer`

**URL Parameter:**

| Param | Type | Description |
|-------|------|-------------|
| `id` | integer | Target user's database ID |

**Request Body:** None

**Success Response — `200 OK`:**
```json
{
  "message": "Revoked 2 session(s).",
  "sessions_revoked": 2
}
```

If the user has no active sessions, `sessions_revoked` will be `0`.

---

### `POST /api/users/:id/unflag`

Clears the threat flag and resets the risk score to `0.0` for a user. Used by admins/developers to manually clear false positives from the threat detection system.

**Auth Required:** Yes  
**Minimum Role:** `developer`

**URL Parameter:**

| Param | Type | Description |
|-------|------|-------------|
| `id` | integer | Target user's database ID |

**Request Body:** None

**Success Response — `200 OK`:**
```json
{
  "message": "User 'Vancika' cleared — flag and risk score reset.",
  "user_id": 2
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `404` | User not found | `{ "error": "User ID 99 not found." }` |

---

### `PUT /api/users/:id/role`

Updates the RBAC role assignment for a user. Multiple security constraints are enforced:
- Users cannot change their own role
- Developers can only assign `guest` roles
- Developers cannot modify `admin` accounts

**Auth Required:** Yes  
**Minimum Role:** `developer`

**URL Parameter:**

| Param | Type | Description |
|-------|------|-------------|
| `id` | integer | Target user's database ID |

**Request Body:**
```json
{
  "role": "developer"
}
```

| Field | Type | Required | Allowed Values |
|-------|------|----------|----------------|
| `role` | string | ✅ | `guest`, `developer`, `admin` |

**Success Response — `200 OK`:**
```json
{
  "message": "Role updated to 'developer' for user 'Vancika'.",
  "user_id": 2,
  "new_role": "developer"
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `400` | Invalid role value | `{ "error": "Invalid role. Must be admin, developer, or guest." }` |
| `400` | Self-role change | `{ "error": "You cannot change your own role." }` |
| `403` | Developer assigning non-guest | `{ "error": "Forbidden", "detail": "Developers can only assign Guest roles." }` |
| `403` | Developer modifying admin | `{ "error": "Forbidden", "detail": "Developers cannot modify Administrator accounts." }` |
| `404` | User not found | `{ "error": "User ID 99 not found." }` |

---

### `DELETE /api/users/:id`

**Permanently** deletes a user account and all associated forensic data (syscall logs and sessions). This action is irreversible. Cannot be used to delete your own account.

**Auth Required:** Yes  
**Minimum Role:** `admin`

**URL Parameter:**

| Param | Type | Description |
|-------|------|-------------|
| `id` | integer | Target user's database ID |

**Request Body:** None

**Success Response — `200 OK`:**
```json
{
  "message": "User 'GuestA' and all associated forensic data permanently deleted.",
  "user_id": 5
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `403` | Attempting to delete own account | `{ "error": "Forbidden", "detail": "You cannot delete your own administrative account." }` |
| `404` | User not found | `{ "error": "User ID 99 not found." }` |

**Side Effects (in order):**
1. `DELETE FROM sessions WHERE user_id = ?` — invalidates all active sessions
2. `DELETE FROM syscall_logs WHERE user_id = ?` — wipes forensic log history
3. `DELETE FROM users WHERE id = ?` — removes the user record

---

## 4. Policy Management

Security policies are JSON rule-sets stored in the database that govern whether a given syscall type is permitted for a given role under specific conditions (e.g., risk score thresholds).

### `GET /api/policies`

Returns all security policies with full rule JSON. For Admin/Developer use.

**Auth Required:** Yes  
**Minimum Role:** `developer`

**Success Response — `200 OK`:**
```json
[
  {
    "id": 1,
    "name": "Block High-Risk Users",
    "rule_json": {
      "call_type": "file_write",
      "condition": "risk_score >= 80",
      "action": "block"
    },
    "is_active": true,
    "created_at": "2026-04-01T10:00:00"
  }
]
```

---

### `GET /api/policies/preview`

Returns a sanitized preview of active policies — only `id`, `name`, and `is_active` are exposed. No rule internals. Intended for Developer-level read-only visibility.

**Auth Required:** Yes  
**Minimum Role:** `developer`

**Success Response — `200 OK`:**
```json
[
  { "id": 1, "name": "Block High-Risk Users", "is_active": true },
  { "id": 2, "name": "Guest Read-Only Mode", "is_active": true }
]
```

Only returns policies where `is_active = true`.

---

### `POST /api/policies`

Creates a new security mediation policy. After creation, the policy engine is hot-reloaded.

**Auth Required:** Yes  
**Minimum Role:** `admin`

**Request Body:**
```json
{
  "name": "Block Exec for Guests",
  "rule_json": {
    "call_type": "exec_process",
    "roles": ["guest"],
    "action": "block",
    "reason": "Guests are not permitted to execute processes."
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✅ | Human-readable policy name (must be unique) |
| `rule_json` | object | ✅ | The policy rule definition |

**Success Response — `201 Created`:**
```json
{
  "message": "Policy created successfully.",
  "id": 3
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `400` | Missing name or rule_json | `{ "error": "name and rule_json are required." }` |
| `400` | Invalid rule_json schema | `{ "error": "<validation message>" }` |
| `409` | Policy name already exists | `{ "error": "<conflict message>" }` |

**Side Effects:** Calls `load_permissions()` to hot-reload the RBAC permission map after creation.

---

### `PUT /api/policies/:id`

Updates an existing policy's rule JSON and/or its active status. After update, the policy engine and RBAC permissions are hot-reloaded.

**Auth Required:** Yes  
**Minimum Role:** `admin`

**URL Parameter:**

| Param | Type | Description |
|-------|------|-------------|
| `id` | integer | Policy database ID |

**Request Body (at least one field required):**
```json
{
  "is_active": false
}
```

or

```json
{
  "rule_json": {
    "call_type": "file_write",
    "roles": ["guest"],
    "action": "block"
  },
  "is_active": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rule_json` | object | ❌ | Updated rule definition |
| `is_active` | boolean | ❌ | Enable (`true`) or disable (`false`) the policy |

**Success Response — `200 OK`:**
```json
{
  "message": "Policy updated."
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `400` | Neither field provided | `{ "error": "Provide at least one of: rule_json, is_active." }` |
| `400` | Invalid rule_json schema | `{ "error": "<validation message>" }` |
| `404` | Policy ID not found | `{ "error": "<not found message>" }` |

**Side Effects:** Calls `reload_policies()` and `load_permissions()` to apply changes live.

---

### `DELETE /api/policies/:id`

Permanently removes a security policy from the database and reloads the policy engine.

**Auth Required:** Yes  
**Minimum Role:** `admin`

**URL Parameter:**

| Param | Type | Description |
|-------|------|-------------|
| `id` | integer | Policy database ID |

**Request Body:** None

**Success Response — `200 OK`:**
```json
{
  "success": true,
  "message": "Policy deleted."
}
```

**Side Effects:** Calls `reload_policies()` to remove the policy from the active rule-set.

---

### `GET /api/policies/export`

Downloads the complete policy rule-set as a JSON document. Useful for backup or transferring policies between environments.

**Auth Required:** Yes  
**Minimum Role:** `admin`

**Success Response — `200 OK`:**
```json
[
  {
    "id": 1,
    "name": "Block High-Risk Users",
    "rule_json": { ... },
    "is_active": true,
    "created_at": "2026-04-01T10:00:00"
  }
]
```

---

### `POST /api/policies/import`

Bulk-imports a JSON array of policy definitions. Useful for restoring a backed-up rule-set or deploying a policy set from a different environment.

**Auth Required:** Yes  
**Minimum Role:** `admin`

**Request Body:** A JSON array of policy objects (same format as the export response)
```json
[
  {
    "name": "Restored Policy 1",
    "rule_json": { "call_type": "file_delete", "action": "block" },
    "is_active": true
  }
]
```

**Success Response — `200 OK`:**
```json
{
  "message": "Successfully imported 3 security policies."
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `400` | Body is not a JSON array | `{ "error": "Expected a JSON list of policies." }` |
| `500` | Database error during import | `{ "error": "<error message>" }` |

---

## 5. Syscall Gateway

All syscall endpoints go through the **Triple-Lock Forensic Lifecycle**:

1. **RBAC Check** (`can_perform(role, permission)`) — role must have the permission
2. **Policy Evaluation** (`evaluate(call_type, role, context)`) — active policies may block based on risk score or other conditions
3. **Input Validation** — path sanitization, command whitelisting, write data limits
4. **Execution** — the actual OS operation inside the sandboxed `./sandbox` directory
5. **Audit Logging** — every decision (allowed or blocked) is written to `syscall_logs` with a SHA-256 hash chain entry
6. **Threat Analysis** — `analyze_event()` evaluates heuristic rules R2-R5 in real time

**RBAC Permissions by Role:**

| Syscall | admin | developer | guest |
|---------|:-----:|:---------:|:-----:|
| `file_read` | ✅ | ✅ | ✅ |
| `file_write` | ✅ | ✅ | ❌ |
| `file_delete` | ✅ | ❌ | ❌ |
| `dir_list` | ✅ | ✅ | ❌ |
| `exec_process` | ✅ | ❌ | ❌ |
| `system_info` | ✅ | ✅ | ✅ |

**Blocked Response (any syscall):**
```json
{
  "status": "blocked",
  "reason": "Your role 'guest' does not have permission to perform 'file_write'."
}
```
HTTP status code is `403`.

**Allowed Response** varies by call type — see individual endpoints below.

---

### `POST /api/syscall/read`

Reads the contents of a file inside the sandbox directory.

**Auth Required:** Yes  
**Minimum Role:** Any (guest+)

**Request Body:**
```json
{
  "file_path": "reports/audit_summary.txt"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file_path` | string | ✅ | Path to the file (relative to sandbox root) |

**Path Validation Rules:**
- Must not contain `..` (path traversal)
- Must not start with `/etc`, `/root`, `/sys`, `/proc`, `/bin`, `/usr`, `/boot`, `/dev`, `/var`
- After resolution, must stay inside `SANDBOX_ROOT`
- Must not contain null bytes (`\x00`)

**Success Response — `200 OK`:**
```json
{
  "status": "allowed",
  "content": "Forensic audit completed.\nAll 56 calls verified.\nNo anomalies detected."
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `400` | Missing file_path | `{ "error": "file_path is required." }` |
| `403` | RBAC/Policy/Validation block | `{ "status": "blocked", "reason": "<reason>" }` |

---

### `POST /api/syscall/write`

Writes data to a file inside the sandbox. Supports four write modes with an optional byte offset for precision writes.

**Auth Required:** Yes  
**Minimum Role:** `developer`

**Request Body:**
```json
{
  "file_path": "output/report.txt",
  "data": "New forensic content here.",
  "mode": "truncate",
  "offset": 0
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file_path` | string | ✅ | Target file path (relative to sandbox root) |
| `data` | string | ✅ | Content to write. Max size: **10 MB** |
| `mode` | string | ❌ | Write mode (default: `truncate`) |
| `offset` | integer | ❌ | Byte offset for `offset` mode (default: `0`) |

**Write Modes:**

| Mode | Python Equivalent | Behaviour |
|------|-------------------|-----------|
| `truncate` | `open(f, 'w')` | Overwrites file completely. Default. |
| `append` | `open(f, 'a')` | Appends data to end of file |
| `overwrite` | `open(f, 'r+')` then `seek(0)` | Writes from position 0, preserving bytes after write length |
| `offset` | `open(f, 'r+')` then `seek(n)` | Writes at the specified byte position |

For `overwrite` and `offset` modes, if the file does not exist it is created first.

**Success Response — `200 OK`:**
```json
{
  "status": "allowed",
  "message": "Write (truncate) successful"
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `400` | Missing file_path | `{ "error": "file_path is required." }` |
| `403` | RBAC/Policy/Validation block | `{ "status": "blocked", "reason": "<reason>" }` |

---

### `POST /api/syscall/delete`

Deletes a file from the sandbox. Only individual files can be deleted — directories are not permitted.

**Auth Required:** Yes  
**Minimum Role:** `admin`

**Request Body:**
```json
{
  "file_path": "temp/old_report.txt"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file_path` | string | ✅ | Path to the file to delete |

**Success Response — `200 OK`:**
```json
{
  "status": "allowed",
  "message": "File deleted: temp/old_report.txt"
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `400` | Missing file_path | `{ "error": "file_path is required." }` |
| `403` | RBAC/Policy/Validation block | `{ "status": "blocked", "reason": "<reason>" }` |

---

### `POST /api/syscall/dir_list`

Lists the contents of a directory inside the sandbox, returning each entry's name, type, and size.

**Auth Required:** Yes  
**Minimum Role:** `developer`

**Request Body:**
```json
{
  "file_path": "reports"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file_path` | string | ✅ | Directory path to list (relative to sandbox root) |

**Success Response — `200 OK`:**
```json
{
  "status": "allowed",
  "entries": [
    { "name": "audit", "type": "dir", "size": null },
    { "name": "audit_summary.txt", "type": "file", "size": 1024 },
    { "name": "report_v2.txt", "type": "file", "size": 512 }
  ]
}
```

Entries are sorted: directories first (`type: "dir"`), then files, both alphabetically.

---

### `GET /api/syscall/explorer`

A convenience endpoint that lists the root of the sandbox directory. Equivalent to calling `POST /api/syscall/dir_list` with `{ "file_path": "." }`.

**Auth Required:** Yes  
**Minimum Role:** `developer`

**Request Body:** None

**Success Response — `200 OK`:**
```json
{
  "status": "allowed",
  "entries": [
    { "name": "output", "type": "dir", "size": null },
    { "name": "reports", "type": "dir", "size": null },
    { "name": "security_audit_v1.txt", "type": "file", "size": 248 }
  ]
}
```

---

### `POST /api/syscall/execute`

Executes a whitelisted shell command inside the sandbox directory with a 5-second timeout.

**Auth Required:** Yes  
**Minimum Role:** `admin`

**Request Body:**
```json
{
  "command": "ls -la"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | string | ✅ | Command string to execute |

**Command Validation (two layers):**

Layer 1 — `validation.py` (`ALLOWED_COMMANDS` whitelist):
```
ls, pwd, whoami, echo, cat, head, tail, python3, python, node, java,
grep, find, mkdir, touch, cp, mv, wc, sort, uniq,
dir, type, cls, ver, copy, move, del, attrib,
hostname, ipconfig, netstat
```

Layer 2 — `validation.py` (`BLOCKED_PATTERNS` regex):
| Pattern | Threat |
|---------|--------|
| `;\s*rm\s` | Chained deletion |
| `\|\s*sh` | Shell pipe injection |
| `&&\s*curl` | Network chaining |
| `>\s*/etc` | Unauthorized redirect |
| `` `.*` `` | Backtick command substitution |
| `\$\(` | Dollar-sign command substitution |
| `\.\.\/` | Path traversal |

Layer 3 — `syscall_wrapper.py` (`BLOCKED_COMMANDS` denylist):
```
rm, rmdir, dd, mkfs, shutdown, reboot, halt, sudo, su, chmod, chown,
kill, pkill, wget, curl, nc, netcat, bash, sh, python, perl,
iptables, passwd, useradd, userdel
```

Commands are run with `subprocess.run(..., timeout=5, cwd=SAFE_BASE_DIR)` — sandboxed to the `user_sandbox` directory context.

**Success Response — `200 OK`:**
```json
{
  "status": "allowed",
  "output": "total 48\n-rw-r--r-- 1 user group 1024 Apr 7 10:00 audit.txt\n",
  "stderr": ""
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `400` | Missing command | `{ "error": "command is required." }` |
| `403` | RBAC/Policy/Validation block | `{ "status": "blocked", "reason": "<reason>" }` |

---

### `GET/POST /api/syscall/system_info`

Returns gateway operational status and system metadata. This is a safe informational call available to all authenticated roles.

**Auth Required:** Yes  
**Minimum Role:** Any (guest+)

**Request Body:** None (for GET), or empty object (for POST)

**Success Response — `200 OK`:**
```json
{
  "status": "allowed",
  "message": "SysCallGuardian Gateway Operational",
  "content": "Status: ONLINE\nNodes: 3 Active\nProtected: 256 endpoints\nUptime: 45d 02h 17m\nOS: SecureOS v2.4.1 (Kernel 6.1.12-sg)"
}
```

---

## 6. Forensic Audit Logs

### `GET /api/logs`

Returns a paginated, filterable stream of forensic audit log entries. RBAC determines data visibility:
- **Admin:** Sees all logs for all users, including sensitive `target_path` values
- **Developer:** Sees all logs but `target_path` is redacted for sensitive system paths
- **Guest:** Sees only their own logs (user filter is hard-coded to their own username)

**Auth Required:** Yes  
**Minimum Role:** `guest`

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `user` | string | Filter by username (Admin/Dev only; ignored for Guests) |
| `status` | string | Filter by decision: `allowed`, `blocked`, or `flagged` |
| `call_type` | string | Filter by operation: `file_read`, `file_write`, `file_delete`, `dir_list`, `exec_process`, `system_info` |
| `date` | string | Filter by exact date: `YYYY-MM-DD` |
| `from` | string | Start of datetime range (ISO 8601) |
| `to` | string | End of datetime range (ISO 8601) |
| `page` | integer | Page number (default: `1`) |
| `per_page` | integer | Entries per page (default: `20`) |

**Example Request:**
```
GET /api/logs?status=blocked&call_type=exec_process&page=1&per_page=10
Authorization: Bearer <token>
```

**Success Response — `200 OK`:**
```json
{
  "page": 1,
  "total": 42,
  "logs": [
    {
      "id": 101,
      "user": "GuestA",
      "call_type": "exec_process",
      "target_path": "rm -rf /",
      "status": "blocked",
      "reason": "Command 'rm' is explicitly blocked for security reasons.",
      "risk_delta": 15.0,
      "timestamp": "2026-04-07T10:00:00+00:00",
      "hash_preview": "a3f9c1d2e5b8…"
    }
  ]
}
```

**Sensitive Path Redaction** (for non-admin roles):

Paths matching these prefixes are replaced with `"[REDACTED — restricted path]"`:
- `/etc/shadow`
- `/etc/passwd`
- `/root/`
- `/home/admin`
- `/sys/`

---

### `GET /api/logs/verify`

Performs a full cryptographic chain verification across the entire forensic log database. Iterates every log entry in order, recomputes the expected SHA-256 hash from data fields, and cross-checks that `prev_hash` links are intact.

**Auth Required:** Yes  
**Minimum Role:** `admin`

**Request Body:** None

**Success Response — `200 OK` (clean chain):**
```json
{
  "status": "valid",
  "message": "Logs are not tampered. Chain integrity verified.",
  "tampered_ids": []
}
```

**Response when tampering detected:**
```json
{
  "status": "tampered",
  "message": "Tampering detected in 2 log entries.",
  "tampered_ids": [47, 48]
}
```

**Hash recomputation formula:**
```python
sha256(json.dumps({
    "user_id":     <int>,
    "call_type":   <str>,
    "target_path": <str>,
    "status":      <str>,
    "reason":      <str>,
    "risk_delta":  <float>,
    "timestamp":   <str>,
    "prev_hash":   <str>   # "GENESIS" for first entry
}, sort_keys=True).encode())
```

Any modification of any field in any log row will cause the stored `log_hash` to diverge from the recomputed value, flagging that row as tampered.

---

### `GET /api/logs/verify/:id`

Verifies the cryptographic integrity of a single specific log entry.

**Auth Required:** Yes  
**Minimum Role:** `admin`

**URL Parameter:**

| Param | Type | Description |
|-------|------|-------------|
| `id` | integer | The log entry `id` to verify |

**Success Response — `200 OK` (clean):**
```json
{
  "log_id": 47,
  "valid": true,
  "tampered": false,
  "message": "Hash verified."
}
```

**Response when tampered:**
```json
{
  "log_id": 47,
  "valid": false,
  "tampered": true,
  "message": "Hash mismatch — entry may have been tampered."
}
```

**Response when not found:**
```json
{
  "log_id": 999,
  "valid": false,
  "tampered": false,
  "message": "Log entry not found."
}
```

---

## 7. Threat Intelligence

### `GET /api/threats`

Returns all users who are currently flagged (`is_flagged = 1`) or have a risk score ≥ 20, ordered by risk score descending. Includes the triggering reason from the in-memory threat log.

**Auth Required:** Yes  
**Minimum Role:** `admin`

**Request Body:** None

**Success Response — `200 OK`:**
```json
[
  {
    "user_id": 2,
    "username": "Vancika",
    "role": "developer",
    "risk_score": 75.0,
    "risk_level": "critical",
    "reason": "Risk score threshold exceeded: 75.0",
    "time": "2026-04-07T09:45:00"
  },
  {
    "user_id": 5,
    "username": "GuestA",
    "role": "guest",
    "risk_score": 30.0,
    "risk_level": "medium",
    "reason": "Denied file_read attempted on sensitive target",
    "time": "2026-04-07T09:12:00"
  }
]
```

**Risk Level Classification:**

| Score Range | Level |
|-------------|-------|
| 0–19 | `low` |
| 20–39 | `medium` |
| 40–69 | `high` |
| 70–100 | `critical` |

**How threats are detected — Heuristic Rules:**

| Rule | Name | Trigger |
|------|------|---------|
| R2 | Syscall Flood | ≥ 5 calls of same type in 60 seconds |
| R3 | Exec Violation | ≥ 1 blocked `exec_process` in 5 minutes |
| R4 | System Path Probe | Access attempt to `/sys`, `/proc`, `/boot`, `/dev`, `/root`, `/etc`, `C:/Windows/System32` |
| R5 | Risk Threshold | Cumulative `risk_score ≥ 70` |

> **Note:** The in-memory threat log (`_threat_log`) resets on server restart. Flagged status and risk score persist in the database.

---

### `GET /api/threats/events`

Returns the raw chronological list of all individual threat detection events captured during the current server session, most recent first.

**Auth Required:** Yes  
**Minimum Role:** `admin`

**Request Body:** None

**Success Response — `200 OK`:**
```json
[
  {
    "user_id": 2,
    "username": "Vancika",
    "reason": "Repeated exec_process violations: 1 in 5 min",
    "time": "2026-04-07T09:45:00.123456",
    "level": "high",
    "risk_level": "high"
  },
  {
    "user_id": 5,
    "username": "GuestA",
    "reason": "System path probe attempt: '/etc/shadow'",
    "time": "2026-04-07T09:12:00.654321",
    "level": "high",
    "risk_level": "high"
  }
]
```

---

## 8. Dashboard Analytics

All dashboard endpoints enforce RBAC data isolation:
- **Admin:** Sees aggregated data across all users; can filter by user/role/status/call_type
- **Developer/Guest:** Hard-locked to their own username; `role` filter is disabled

### `GET /api/dashboard/stats`

High-level summary statistics: total syscall volume, breakdown by status, flagged user count, and top 5 most active users.

**Auth Required:** Yes  
**Minimum Role:** `guest`

**Query Parameters (Admin only; ignored for lower roles):**

| Param | Type | Description |
|-------|------|-------------|
| `user` | string | Filter stats for a specific username |
| `status` | string | `allowed`, `blocked`, or `flagged` |
| `call_type` | string | One of the 6 syscall types |
| `role` | string | `guest`, `developer`, or `admin` |

**Success Response — `200 OK`:**
```json
{
  "total_calls": 356,
  "allowed": 298,
  "blocked": 41,
  "flagged": 17,
  "suspicious_users": 3,
  "top_users": [
    { "username": "Tejax", "call_count": 56 },
    { "username": "Vancika", "call_count": 26 },
    { "username": "GuestA", "call_count": 12 }
  ]
}
```

> `suspicious_users` is only populated for Admins; it returns `0` for all other roles.

---

### `GET /api/dashboard/activity`

Returns an hourly timeline of syscall activity (allowed vs. blocked) for the **last 24 hours**. Used to render the time-series chart on the Overview page.

**Auth Required:** Yes  
**Minimum Role:** `guest`

**Query Parameters:** Same as `/api/dashboard/stats`

**Success Response — `200 OK`:**
```json
[
  { "hour": "08:00", "allowed": 12, "blocked": 1, "calls": 13 },
  { "hour": "09:00", "allowed": 24, "blocked": 3, "calls": 27 },
  { "hour": "10:00", "allowed": 18, "blocked": 0, "calls": 18 }
]
```

Hours without any activity are omitted (not returned as zero-rows).

---

### `GET /api/dashboard/extended`

Returns the complete extended dataset used by the advanced analytics dashboard. Provides five datasets in a single request to minimize round-trips.

**Auth Required:** Yes  
**Minimum Role:** `guest`

**Query Parameters:** Same as `/api/dashboard/stats`

**Success Response — `200 OK`:**
```json
{
  "heatmap": [
    { "username": "Tejax", "call_type": "file_read", "count": 30 },
    { "username": "Vancika", "call_type": "file_write", "count": 14 }
  ],
  "syscall_status": [
    { "call_type": "file_read", "status": "allowed", "count": 210 },
    { "call_type": "exec_process", "status": "blocked", "count": 8 }
  ],
  "role_dist": [
    { "role": "admin", "count": 56 },
    { "role": "developer", "count": 26 },
    { "role": "guest", "count": 12 }
  ],
  "user_risks": [
    { "username": "Tejax", "risk_score": 0.0 },
    { "username": "Vancika", "risk_score": 75.0 }
  ],
  "recent_logs": [
    {
      "user": "GuestA",
      "call_type": "file_read",
      "status": "allowed",
      "timestamp": "2026-04-07T10:00:00",
      "target_path": "reports/audit.txt"
    }
  ]
}
```

**Dataset Descriptions:**

| Key | Description |
|-----|-------------|
| `heatmap` | Per-user, per-call-type call counts (used for the User × Syscall heatmap) |
| `syscall_status` | Call type broken down by decision status (used for stacked bar chart) |
| `role_dist` | Syscall count grouped by user role (used for role distribution chart) |
| `user_risks` | All users with their current risk scores (used for risk leaderboard) |
| `recent_logs` | Last 100 log entries, with path redaction for non-admin roles (used for Forensic Scatter Stream) |

**Sensitive Path Redaction** applies to `recent_logs` for non-admin users (same prefixes as `/api/logs`).

---

## Error Reference

### Common HTTP Status Codes

| Code | Meaning | When It Occurs |
|------|---------|----------------|
| `200` | OK | Successful request |
| `201` | Created | Resource successfully created |
| `400` | Bad Request | Missing required fields, validation failure |
| `401` | Unauthorized | No token, invalid token, or expired session |
| `403` | Forbidden | Valid token but insufficient role, or self-action prevention |
| `404` | Not Found | Requested resource (user, policy, log) does not exist |
| `409` | Conflict | Duplicate resource (e.g. username already taken) |
| `500` | Internal Server Error | Database error or unexpected server-side failure |

### Standard Error Body

All error responses follow this shape:
```json
{
  "error": "Human-readable error message.",
  "detail": "Optional additional context for certain 403 responses."
}
```

### Syscall-Specific Block Body

When a syscall is blocked (as opposed to an auth failure), the HTTP status is `403` and the body uses the syscall response format:
```json
{
  "status": "blocked",
  "reason": "Descriptive reason explaining why the syscall was rejected."
}
```

---

*SysCallGuardian API Documentation — v1.0 Final Release*  
*Covers all endpoints from `auth_routes.py`, `log_routes.py`, and `syscall_routes.py`*
