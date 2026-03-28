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
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            name                TEXT NOT NULL,
            ip_address          TEXT NOT NULL UNIQUE,
            device_type         TEXT NOT NULL DEFAULT 'Unknown',
            ssh_username        TEXT,
            ssh_password        TEXT,  -- TODO: encrypt in production
            netmiko_device_type TEXT,
            created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Migration: add netmiko_device_type to existing databases
    try:
        c.execute('ALTER TABLE devices ADD COLUMN netmiko_device_type TEXT')
        conn.commit()
    except Exception:
        pass  # Column already exists

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

    c.execute('''
        CREATE TABLE IF NOT EXISTS config_backups (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id   INTEGER NOT NULL,
            config_text TEXT NOT NULL,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
        # Ping-only devices
        c.executemany(
            'INSERT INTO devices (name, ip_address, device_type) VALUES (?, ?, ?)',
            [
                ('Google DNS',     '8.8.8.8',     'DNS Server'),
                ('Cloudflare DNS', '1.1.1.1',     'DNS Server'),
                ('Oracle VM',      '92.5.48.191', 'Virtual Machine'),
            ]
        )
        # Cisco DevNet Sandbox — SSH-capable device
        # NOTE: In production, ssh_password should be stored encrypted (e.g. with cryptography.fernet)
        c.execute(
            'INSERT INTO devices '
            '(name, ip_address, device_type, ssh_username, ssh_password, netmiko_device_type) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (
                'Cisco DevNet Sandbox',
                'devnetsandboxiosxec8k.cisco.com',
                'Cisco IOS XE',
                'm.madzin',
                'szmF8H9Wf1--R',
                'cisco_xe',
            ),
        )
        conn.commit()
    conn.close()
