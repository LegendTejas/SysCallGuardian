# SysCallGuardian — Viva Preparation Sheet

---

## Demo Order (practice exactly in this sequence)

### Scenario 1 — Normal Admin Flow (60 sec)
1. Login as admin
2. Dashboard loads — real stats from DB
3. System Calls page → Execute: `ls -la`
4. Terminal: ALLOWED + output shown
5. Audit Logs page → call appears with SHA-256 hash
6. Click "Verify Integrity" → valid chain confirmed

**Demonstrates:** Auth flow, RBAC allow, execution, logging, integrity

---

### Scenario 2 — Guest RBAC Block (60 sec)
1. Login as guest
2. System Calls page → notice ✗ chips for exec_process, file_write
3. Execute: `ls -la` → BLOCKED (lacks exec_process permission)
4. Write File: test.txt → BLOCKED (lacks file_write permission)
5. Read File: test.txt → ALLOWED (guest has file_read)

**Demonstrates:** RBAC enforcement at middleware level

---

### Scenario 3 — Path Traversal Attack (45 sec)
1. Login as admin (even admin cannot bypass validation)
2. Read File: `../../etc/passwd` → BLOCKED (path traversal)
3. Read File: `/etc/shadow` → BLOCKED (system path blocklist)

**Demonstrates:** Input validation layer, defense in depth

---

### Scenario 4 — Threat Detection Live (90 sec)
1. Login as guest
2. Attempt Execute Process 3 times (any command)
3. Go to Threats page → guest appears with elevated risk score
4. Users page → guest shows 🔴 flagged
5. Audit Logs → filter by guest → all blocked attempts visible
6. Verify Integrity → chain valid despite all the blocks

**Demonstrates:** Threat detection Rule R3, risk scoring, audit trail

---

### Scenario 5 — Policy Toggle Live Effect (90 sec)
1. Login as admin → Policies page
2. Disable `block_guest_exec` (toggle off)
3. Logout → Login as guest
4. Execute: `ls` → ALLOWED (policy was disabled)
5. Logout → Login as admin → Re-enable policy
6. Login as guest again → Execute → BLOCKED again

**Demonstrates:** Dynamic policy engine — runtime changes, no restart needed

---

### Scenario 6 — Live Policy Create (2 min)
1. Login as admin → Policies page → click "+ New Policy"
2. Fill form: action=file_read, deny_roles=[developer]
3. Create → appears in list as ACTIVE
4. Logout → Login as developer
5. System Calls → Read File: test.txt → BLOCKED by new policy
6. Login as admin → disable the policy
7. Login as developer → Read File → ALLOWED again

**Demonstrates:** Policy editor, rule creation, instant runtime effect

---

### Scenario 7 — User Management (60 sec)
1. Login as admin → Users page → real data loads
2. Click guest user → modal shows real stats, risk bar
3. Change role: guest → developer → Save Role
4. Logout → Login as guest (now developer)
5. Write File → ALLOWED (developer has file_write)

**Demonstrates:** Live user management, role change takes effect immediately

---

## Viva Q&A

### Tejas — Auth + RBAC + Policy Engine

**Q: Why bcrypt over SHA-256 for passwords?**
SHA-256 is a fast hash — it can compute billions per second, making brute force trivial. bcrypt is intentionally slow with a configurable work factor and auto-generates a salt per password. Even with the same password, two bcrypt hashes are different. This makes rainbow table attacks and brute force computationally expensive.

**Q: What is inside your JWT token?**
The payload contains: `user_id`, `username`, `role`, `exp` (expiry timestamp), `iat` (issued at), and `jti` (unique token ID). The `jti` ensures every token is unique — even two logins by the same user at the same time get different tokens, preventing replay attacks.

**Q: How does your policy engine work differently from if-else?**
Hardcoded if-else requires a code change and server restart to modify rules. Our engine reads rules from the `policies` table in the DB at runtime. An admin creates, updates, or disables policies through the API and the in-memory cache reloads immediately — the server keeps running. This is the same concept as AWS IAM policies.

**Q: What is the performance overhead of your mediation layer?**
Direct file read: ~0.02ms. Full mediation stack (auth + RBAC + policy + syscall): ~0.9ms. That's roughly 40x slower in absolute time, but 0.88ms extra per call is acceptable for a security system. In production you would cache JWT validation results and policy lookups.

**Q: What happens if two users log in simultaneously?**
Each login generates a JWT with a unique `jti` UUID. Both tokens are stored as separate rows in the `sessions` table. Both are valid independently until logout or expiry.

**Q: What does `deny_roles` do that `allow_roles` doesn't already handle?**
`deny_roles` is evaluated first and is absolute — even if a role appears in `allow_roles`, if it's in `deny_roles` it's blocked. This allows you to write a rule like "allow all except guest" by setting `allow_roles: [admin, developer]` AND `deny_roles: [guest]` for belt-and-suspenders security.

---

### Vanshika — Syscall Layer + Logging + Threat Detection

**Q: Why `shell=False` in subprocess.run?**
With `shell=True`, the command string goes to `/bin/sh -c`, which interprets `;`, `|`, `&&`, `$()`, backticks. An attacker can append `; rm -rf /` and it runs. With `shell=False`, the command is split into tokens and passed directly to `execvp`. The shell never sees it. Injection is structurally impossible regardless of the input.

**Q: How does SHA-256 hash chaining detect tampering?**
Each log entry stores a hash of its own data fields plus the hash of the previous entry (`prev_hash`). If someone edits entry #5's data, its hash changes. But entry #6 stores the old hash of #5 as its `prev_hash`. When `verify_all_logs()` recomputes the chain, it sees that entry #6's `prev_hash` no longer matches entry #5's current hash. The tampered entry is identified exactly.

**Q: What if someone deletes a log entry?**
If entry #5 is deleted, entry #6's `prev_hash` now points to a hash that doesn't exist. The verifier walks entries in ID order — it sees that entry #6's `prev_hash` doesn't match what is now the previous entry. Any deletion breaks the chain and is detected.

**Q: What is a sliding window and why use it?**
A sliding window keeps only events from the last N seconds (we use 300 seconds). When a new event arrives we prune events older than 300 seconds. This gives a fair rolling view — a user with 25 failed calls from 10 minutes ago isn't flagged forever, but a user with 25 failed calls in the last 60 seconds triggers the flood rule immediately.

**Q: What is path traversal and how do you prevent it?**
An attacker provides `../../etc/passwd` to escape the intended directory. We prevent it at two layers: first `validate_file_path()` rejects any path containing `..`. Second, `os.path.normpath()` resolves the canonical path, which we check against a blocklist of restricted system paths. Both must pass before any file operation runs.

**Q: Why use a command whitelist instead of a blocklist for exec_process?**
Blocklists can be bypassed — there are always commands the developer forgot to block. A whitelist only permits known-safe commands. If a command isn't in the list, it's blocked by default. This is the principle of least privilege applied to process execution.

---

### Akhil — Frontend + Integration

**Q: What is CORS and why do you need it?**
CORS (Cross-Origin Resource Sharing) is a browser security policy that blocks JavaScript from fetching resources from a different origin than the page was loaded from. Our frontend runs on port 8080 (or file://) and Flask runs on port 5000 — different origins. Flask-CORS adds `Access-Control-Allow-Origin` headers so the browser permits these requests.

**Q: Walk through the JWT flow from login to a protected route.**
Login sends credentials to `POST /api/auth/login`. Server verifies bcrypt, generates JWT, stores session in DB, returns token. Frontend stores token in `localStorage`. Every fetch adds `Authorization: Bearer <token>`. The `@require_auth` decorator extracts the token, calls `validate_session()` which verifies the signature and checks the sessions table. If valid, `g.user` is set. If not, 401 is returned, the frontend clears localStorage and redirects to login.

**Q: Why paginate logs?**
After weeks of use the `syscall_logs` table could have hundreds of thousands of entries. Fetching all at once would be slow to query, transfer megabytes of JSON, block the browser while parsing, and crash the render. Pagination fetches only 8–20 rows per request and gives instant response.

**Q: How would you add real-time updates without polling?**
WebSockets maintain a persistent connection between browser and server. Instead of polling `GET /api/dashboard/stats` every 5 seconds, Flask-SocketIO pushes new events to connected clients whenever a syscall is logged. The frontend registers `socket.on('new_log', updateFeed)`. No polling latency, lower server load.

**Q: What happens when the backend is down?**
The `api()` wrapper catches network errors (`fetch` throws on connection failure). It shows a toast: "Cannot reach server. Is the backend running?" and returns `{ ok: false, status: 0 }`. Every page handles this by displaying an error message instead of crashing.

---

## Key Numbers to Remember

| Metric | Value |
|---|---|
| Test cases total | ~137 (28 + 32 + 42 + 35) |
| API endpoints | 22 |
| Threat detection rules | 5 (R2 flood, R3 exec blocks, R4 sys path, R5 high risk) |
| Risk score range | 0.0 – 100.0 |
| Risk increment per blocked exec | +15.0 |
| Risk increment per blocked system_dir | +20.0 |
| Flagging threshold | risk_score ≥ 70 OR 5 failed logins |
| Token expiry | 8 hours |
| Subprocess timeout | 10 seconds |
| Max output per exec | 8 KB |
| Max file write | 10 MB |
| Hash algorithm | SHA-256 (64 hex chars) |
| Default policies seeded | 5 |
| RBAC roles | 3 (admin, developer, guest) |
| Mediation overhead | ~0.88ms per call |

---

## One-line definitions (for quick recall)

- **RBAC**: permission check based on the user's role, enforced at middleware level before any business logic runs
- **Policy Engine**: dynamic rule evaluator that reads JSON rules from the DB at runtime — no server restart needed to change rules
- **Hash chaining**: each log entry stores SHA-256(its own data + previous entry's hash), making any edit or deletion detectable
- **Threat detection**: sliding window of recent events per user, rule-based flagging when patterns exceed thresholds
- **Risk scoring**: cumulative float (0–100) incremented on blocked/flagged calls, used as a condition in policies
- **Sandbox root**: base directory for all file operations — relative paths resolve inside it, absolute system paths are blocked
- **JWT jti claim**: unique ID per token — prevents replay attacks where a captured token is reused

---

*SysCallGuardian Viva Prep · OS Semester 4 · Akhil · Tejas · Vanshika*
