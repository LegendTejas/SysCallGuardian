import sqlite3, bcrypt
conn = sqlite3.connect('syscall_gateway.db')
c = conn.cursor()
try:
    c.execute('ALTER TABLE users ADD COLUMN email TEXT')
    print('Added email column successfully')
except Exception as e:
    print('Failed to add column:', e)

c.execute("UPDATE users SET username='Tejax', email='tejastp193@gmail.com' WHERE role='admin' AND username='Admin'")
c.execute("INSERT OR IGNORE INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)", ('Tejax', bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode('utf-8'), 'admin', 'tejastp193@gmail.com'))
c.execute("UPDATE users SET email='cvanshika995@gmail.com' WHERE username='Vanshika'")
c.execute("INSERT OR IGNORE INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)", ('Vanshika', bcrypt.hashpw(b'Van123', bcrypt.gensalt()).decode('utf-8'), 'developer', 'cvanshika995@gmail.com'))
c.execute("UPDATE users SET email='guest_user@example.com' WHERE username='guest_x7'")

conn.commit()
conn.close()
print("Seeding complete.")
