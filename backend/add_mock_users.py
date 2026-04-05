import sqlite3
import os
import bcrypt

db_path = "syscall_gateway.db"

def add_users():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    users = [
        ("dev_raj", "Dev123", "developer"),
        ("dev_priya", "Dev123", "developer"),
        ("guest_x7", "Guest123", "guest"),
        ("tejas", "Tejas123", "admin"),
        ("vanshika", "Van123", "developer"),
    ]

    for username, password, role in users:
        pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        try:
            cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                         (username, pwd_hash, role))
            print(f"Added user: {username}")
        except sqlite3.IntegrityError:
            print(f"User {username} already exists.")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    add_users()
