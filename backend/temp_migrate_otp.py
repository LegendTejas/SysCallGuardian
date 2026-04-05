import sqlite3

conn = sqlite3.connect('syscall_gateway.db')
c = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS otps (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        email      TEXT NOT NULL,
        otp_code   TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

conn.commit()
conn.close()
print('otps table created successfully')
