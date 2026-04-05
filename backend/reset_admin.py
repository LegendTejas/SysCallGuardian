from database.db import get_connection
conn = get_connection()
try:
    conn.execute("UPDATE users SET is_flagged=0, risk_score=0.0 WHERE username='admin1'")
    conn.commit()
    print("[DB] admin1 reset success.")
except Exception as e:
    print(f"[DB] Error: {e}")
finally:
    conn.close()
