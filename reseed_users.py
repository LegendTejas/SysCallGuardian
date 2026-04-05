import sqlite3
import bcrypt
import os

DB_PATH = "backend/syscall_gateway.db"

def reseed_users():
    if not os.path.exists(DB_PATH):
        print(f"Error: {DB_PATH} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1. Remove all existing Users
    print("[1/3] Removing existing Users...")
    cursor.execute("DELETE FROM users")
    
    # 2. Define the new users
    new_users = [
        ("Tejax",   "U@itej99x", "admin",     "testingacctejax@gmail.com"), 
        ("Akael",   "Akhil9890", "admin",     None),
        ("Vancika", "Van112358", "developer", "cvanshika995@gmail.com"),
        ("GuestA",  "Guest@123", "guest",     "guest.a@example.com"),
        ("GuestB",  "Guest@456", "guest",     "guest.b@example.com")
    ]

    print("[2/3] Seeding specified users...")
    for username, password, role, email in new_users:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)", 
            (username, hashed, role, email)
        )
        print(f"  -> Created {role}: {username}")

    print("[3/4] Seeding mock syscall activity for all roles...")
    import random
    syscall_types = ["file_read", "file_write", "file_delete", "dir_list", "exec_process", "net_socket"]
    statuses = ["allowed", "allowed", "allowed", "blocked", "flagged"] # Weighting towards allowed
    
    # Get all the newly created users
    users = cursor.execute("SELECT id, username, role FROM users WHERE role IN ('admin', 'developer')").fetchall()
    
    for uid, name, role in users:
        # Create 10-15 random logs for each user
        for _ in range(random.randint(10, 15)):
            call = random.choice(syscall_types)
            status = random.choice(statuses)
            # Create a mock hash for integrity chain
            mock_hash = "mock_hash_" + str(random.getrandbits(64))
            cursor.execute(
                "INSERT INTO syscall_logs (user_id, call_type, status, log_hash, reason) VALUES (?, ?, ?, ?, ?)",
                (uid, call, status, mock_hash, f"Mock activity for {name}")
            )
        print(f"  -> Generated mock logs for: {name} ({role})")

    # 4. Clear sessions for safety
    print("[4/4] Clearing active sessions...")
    cursor.execute("DELETE FROM sessions")

    conn.commit()
    conn.close()
    print("\n[DB] Database users re-seeded successfully.")

if __name__ == "__main__":
    reseed_users()
