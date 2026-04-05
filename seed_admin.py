import sqlite3
import bcrypt
import os

DB_PATH = "backend/syscall_gateway.db"

def seed_admin():
    if not os.path.exists(DB_PATH):
        print(f"Error: {DB_PATH} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    username = "admin"
    password = "Admin123"
    role = "admin"

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        cursor.execute("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                       (username, hashed, role))
        conn.commit()
        print(f"User '{username}' created with password '{password}' and role '{role}'.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    seed_admin()
