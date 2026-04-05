import sqlite3
import os

db_path = "syscall_gateway.db"
if not os.path.exists(db_path):
    print(f"DB {db_path} not found.")
else:
    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM syscall_logs").fetchone()[0]
    print(f"Total Logs: {count}")
    conn.close()
