"""
database/models.py
Schema creation and DB seeding.
Run once: python -m database.models
"""

from database.db import get_connection


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'guest'
                            CHECK(role IN ('admin','developer','guest')),
            is_flagged    INTEGER NOT NULL DEFAULT 0,
            risk_score    REAL NOT NULL DEFAULT 0.0,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS roles (
            role        TEXT PRIMARY KEY,
            permissions TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS policies (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT UNIQUE NOT NULL,
            rule_json  TEXT NOT NULL,
            is_active  INTEGER NOT NULL DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS syscall_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            call_type   TEXT NOT NULL,
            target_path TEXT,
            status      TEXT NOT NULL CHECK(status IN ('allowed','blocked','flagged')),
            reason      TEXT,
            risk_delta  REAL DEFAULT 0.0,
            log_hash    TEXT NOT NULL,
            prev_hash   TEXT,
            timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS otps (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT NOT NULL,
            otp_code   TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Seed roles
    cursor.executemany(
        "INSERT OR REPLACE INTO roles (role, permissions) VALUES (?, ?)",
        [
            ("admin",
             '["file_read","file_write","file_delete","dir_list","exec_process",'
             '"system_dir_access","view_logs","manage_policies","view_dashboard","system_info"]'),
            ("developer",
             '["file_read","file_write","dir_list","exec_process","view_logs","view_dashboard","system_info"]'),
            ("guest",
             '["file_read","dir_list","system_info"]'),
        ]
    )

    # Seed policies
    cursor.executemany(
        "INSERT OR REPLACE INTO policies (name, rule_json, is_active) VALUES (?, ?, ?)",
        [
            ("block_guest_exec",
             '{"action":"exec_process","allow_roles":["admin","developer"],"deny_roles":["guest"]}', 1),
            ("block_guest_write",
             '{"action":"file_write","allow_roles":["admin","developer"],"deny_roles":["guest"]}', 1),
            ("block_guest_delete",
             '{"action":"file_delete","allow_roles":["admin"],"deny_roles":["guest","developer"]}', 1),
            ("restrict_system_dirs",
             '{"action":"system_dir_access","allow_roles":["admin"],"deny_roles":["guest","developer"]}', 1),
            ("high_risk_exec_block",
             '{"action":"exec_process","allow_roles":["admin","developer"],"conditions":{"max_risk_score":60}}', 1),
        ]
    )

    conn.commit()
    conn.close()
    print("[DB] Schema initialized and seeded.")


if __name__ == "__main__":
    init_db()
