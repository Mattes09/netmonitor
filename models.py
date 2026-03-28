import sqlite3
from config import DATABASE


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            ip_address   TEXT NOT NULL UNIQUE,
            device_type  TEXT NOT NULL DEFAULT 'Unknown',
            ssh_username TEXT,
            ssh_password TEXT,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS ping_history (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id     INTEGER NOT NULL,
            status        TEXT NOT NULL,
            response_time REAL,
            checked_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        )
    ''')

    conn.commit()
    conn.close()


def seed_devices():
    """Insert sample devices on first run (no-op if table already has rows)."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM devices')
    if c.fetchone()[0] == 0:
        c.executemany(
            'INSERT INTO devices (name, ip_address, device_type) VALUES (?, ?, ?)',
            [
                ('Google DNS',    '8.8.8.8',      'DNS Server'),
                ('Cloudflare DNS','1.1.1.1',      'DNS Server'),
                ('Oracle VM',     '92.5.48.191',  'Virtual Machine'),
            ]
        )
        conn.commit()
    conn.close()
