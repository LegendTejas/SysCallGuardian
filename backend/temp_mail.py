import sqlite3
conn = sqlite3.connect('syscall_gateway.db')
conn.execute("UPDATE users SET email='testingacctejax@gmail.com' WHERE username='Tejax'")
conn.commit()
conn.close()
print('Database updated testing email safely')
