import sqlite3
import random
import datetime
import os

db_path = "syscall_gateway.db"

def seed():
    if not os.path.exists(db_path):
        print("DB not found.")
        return

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get existing users
    users = cursor.execute("SELECT id, username, role FROM users").fetchall()
    if not users:
        print("No users found. Please run seed_admin.py first.")
        return

    syscalls = ["file_read", "file_write", "file_delete", "dir_list", "exec_process"]
    statuses = ["allowed", "blocked", "flagged"]
    paths = ["/etc/passwd", "/var/log/syslog", "/home/user/docs", "/bin/sh", "/tmp/test.tmp"]

    print(f"Seeding logs for {len(users)} users...")

    now = datetime.datetime.now()
    log_count = 0

    for i in range(150): # 150 random logs
        user = random.choice(users)
        call = random.choice(syscalls)
        status = random.choices(statuses, weights=[0.7, 0.2, 0.1])[0]
        path = random.choice(paths)
        
        # Random timestamp within last 24 hours
        ts = now - datetime.timedelta(minutes=random.randint(0, 1440))
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            INSERT INTO syscall_logs (user_id, call_type, target_path, status, reason, risk_delta, log_hash, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user['id'], 
            call, 
            path, 
            status, 
            "Seeded for analytics demo" if status != "allowed" else None,
            random.uniform(0, 15) if status != "allowed" else 0,
            f"hash_{random.getrandbits(64):x}",
            ts_str
        ))
        log_count += 1
        conn.commit()
    
    # Randomise risk scores for better visualization
    for u in users:
        new_risk = random.uniform(5, 85)
        cursor.execute("UPDATE users SET risk_score = ? WHERE id = ?", (new_risk, u['id']))
    
    conn.commit()
    print(f"Successfully seeded {log_count} logs and updated user risk scores.")
    conn.close()

if __name__ == "__main__":
    seed()
