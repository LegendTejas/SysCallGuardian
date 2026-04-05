from database.db import get_connection
conn = get_connection()
try:
    res = conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()
    print("Triggers:", [r[0] for r in res])
except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()
