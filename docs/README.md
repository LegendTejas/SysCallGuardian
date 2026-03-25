# 📡 API Documentation  
**Project:** Secure System Call Gateway with RBAC & Real-Time Monitoring  

---

## 🔐 Authentication APIs

### 1. Login
**POST** `/api/auth/login`

**Request Body:**
```json
{
  "username": "tejas",
  "password": "password123"
}
```

#### **Response:**

```json
{
  "message": "Login successful",
  "token": "jwt_token_here",
  "role": "admin"
}
```
---

### **2. Logout**

**POST** `/api/auth/logout`

#### **Headers:**
```
Authorization: Bearer <token>
```

#### **Response:**
```json
{
  "message": "Logged out successfully"
}
```

---

## 👤 User & Role APIs

### **3. Get Current User**

**GET** `/api/user/me`

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "username": "tejas",
  "role": "admin"
}
```
---

## ⚙️ System Call APIs

### **4. Read File**

**POST** `/api/syscall/read`

**Request Body:**

```json
{
  "file_path": "test.txt"
}
```

**Response:**
```json
{
  "status": "allowed",
  "content": "File content here"
}
```

---

### **5. Write File**

**POST** `/api/syscall/write`

**Request Body:**
```json
{
  "file_path": "test.txt",
  "data": "Hello World"
}
```

**Response:**
```json
{
  "status": "allowed",
  "message": "Write successful"
}
```

---

### **6. Delete File**

**POST** `/api/syscall/delete`

**Request Body:**
```
{
  "file_path": "test.txt"
}
```

**Response:**
```json
{
  "status": "blocked",
  "reason": "Permission denied"
}
```

---

### **7. Execute Process**

**POST** `/api/syscall/execute`

**Request Body:**

```json
{
  "command": "ls"
}
```

**Response:**
```json
{
  "status": "allowed",
  "output": "file1.txt file2.txt"
}
```

---

## 📜 Logging APIs

### **8. Get Logs**

**GET** `/api/logs`

**Headers:**
```
Authorization: Bearer <token>
```

**Query Params (Optional):**

- `user`
- `status`
- `call_type`
- `date`

**Response:**

```json
[
  {
    "user": "tejas",
    "call": "read_file",
    "status": "allowed",
    "timestamp": "2026-03-25T10:00:00"
  }
]
```
---

### **9. Verify Log Integrity**

**GET** `/api/logs/verify`

**Response:**
```json
{
  "status": "valid",
  "message": "Logs are not tampered"
}
```

---

## 🚨 Threat Detection APIs

### **10. Get Suspicious Activities**

**GET** `/api/threats`

**Response:**

```json
[
  {
    "user": "guest",
    "risk_score": 85,
    "reason": "Multiple failed attempts"
  }
]
```

---

## 📊 Dashboard APIs

### **11. System Statistics**

**GET** `/api/dashboard/stats`

**Response:**

```json
{
  "total_calls": 120,
  "allowed": 90,
  "blocked": 30,
  "suspicious_users": 3
}
```
---

### **12. Activity Over Time**

**GET** `/api/dashboard/activity`

**Response:**

```json
[
  {
    "time": "10:00",
    "calls": 15
  },
  {
    "time": "11:00",
    "calls": 20
  }
]
```

---

## 🔒 Security Notes

- All protected routes require JWT Authentication
- Role-Based Access Control (RBAC) enforced at middleware level
- Policies dynamically loaded from access_policy.json
- All system calls are:
  - Logged
  - Validated
  - Checked against policies

---

## 📌 Status Codes

| Code | Meaning               |
| ---- | --------------------- |
| 200  | Success               |
| 401  | Unauthorized          |
| 403  | Forbidden             |
| 500  | Internal Server Error |

---

## 🧠 Summary

This API layer acts as a secure mediation interface between users and OS system calls by integrating:

- Authentication
- RBAC
- Policy Enforcement
- Secure Logging
- Threat Detection
