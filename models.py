import ipaddress
import re
import sqlite3
from config import DATABASE


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA journal_mode = WAL')
    conn.execute('PRAGMA busy_timeout = 5000')
    return conn


def get_all_devices(sort_key='id'):
    """Return all devices with their latest ping status, sorted by *sort_key*.

    LEFT JOINs each device to its most recent ping_history row, so devices
    with no ping history are still returned (with a null status). Selects
    every device column (d.*) plus the latest status, response_time and
    checked_at — the shared "list devices" query used by the dashboard and
    the JSON API.

    sort_key is mapped through a whitelist to a safe ORDER BY fragment. An
    ORDER BY column name cannot be a bound (?) parameter, so the user's input
    is used only as a dictionary key — never interpolated into SQL — and any
    unrecognised key falls back to 'id'. This is the safe way to do dynamic
    sorting: values are parameterized, identifiers are whitelisted.
    """
    sort_columns = {
        'id':     'd.id',
        'name':   'd.name COLLATE NOCASE',
        'type':   'd.device_type COLLATE NOCASE',
        'status': 'ph.status, d.id',
    }
    order_by = sort_columns.get(sort_key, 'd.id')

    conn = get_db()
    rows = conn.execute(f'''
        SELECT d.*,
               ph.status,
               ph.response_time,
               ph.checked_at AS last_checked
        FROM devices d
        LEFT JOIN ping_history ph ON ph.id = (
            SELECT id FROM ping_history
            WHERE device_id = d.id
            ORDER BY checked_at DESC
            LIMIT 1
        )
        ORDER BY {order_by}
    ''').fetchall()
    conn.close()
    return rows


_HOSTNAME_LABEL = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')


def _is_valid_address(value):
    """Return True if *value* is a valid IP address (v4/v6) or hostname."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    # Treat as a hostname.
    if len(value) > 253:
        return False
    labels = value.split('.')
    if not all(_HOSTNAME_LABEL.match(label) for label in labels):
        return False
    # Reject IP-like strings whose last label is all digits (e.g. 1.2.3.4.5).
    if labels[-1].isdigit():
        return False
    return True


def validate_device_data(data):
    """Validate device *data*; return a list of error strings ([] = valid).

    Only name and ip_address are required — SSH fields and the Netmiko driver
    are optional.
    """
    errors = []
    if not (data.get('name') or '').strip():
        errors.append('Device name is required.')

    ip_address = (data.get('ip_address') or '').strip()
    if not ip_address:
        errors.append('IP address or hostname is required.')
    elif not _is_valid_address(ip_address):
        errors.append(
            'Address must be a valid IP address or hostname '
            '(e.g. 192.168.1.1 or switch.example.com).'
        )

    return errors


def create_device(data):
    """Insert a new device from *data* and return its new id.

    *data* is a dict with keys: name, ip_address, device_type, ssh_username,
    ssh_password, netmiko_device_type (some values may be None). sqlite3 errors
    (e.g. a duplicate ip_address UNIQUE violation) propagate to the caller.
    """
    conn = get_db()
    cursor = conn.execute(
        'INSERT INTO devices '
        '(name, ip_address, device_type, ssh_username, ssh_password, netmiko_device_type) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (
            data['name'],
            data['ip_address'],
            data['device_type'],
            data['ssh_username'],
            data['ssh_password'],
            data['netmiko_device_type'],
        ),
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def update_device(device_id, data):
    """Update all six columns of the device with *device_id* from *data*.

    sqlite3 errors (e.g. a duplicate ip_address UNIQUE violation) propagate to
    the caller. Symmetric with create_device.
    """
    conn = get_db()
    conn.execute(
        'UPDATE devices SET '
        'name = ?, ip_address = ?, device_type = ?, '
        'ssh_username = ?, ssh_password = ?, netmiko_device_type = ? '
        'WHERE id = ?',
        (
            data['name'],
            data['ip_address'],
            data['device_type'],
            data['ssh_username'],
            data['ssh_password'],
            data['netmiko_device_type'],
            device_id,
        ),
    )
    conn.commit()
    conn.close()


def delete_device(device_id):
    """Delete the device with *device_id*.

    Child rows in ping_history and config_backups are removed automatically by
    the ON DELETE CASCADE foreign keys.
    """
    conn = get_db()
    conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
    conn.commit()
    conn.close()


def get_device(device_id):
    """Return a single device row by id, or None if not found."""
    conn = get_db()
    row = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    conn.close()
    return row


def get_ping_history(device_id, limit=100):
    """Return a device's ping_history rows, newest first, capped at *limit*.

    Mirrors the device-detail view (last 100, newest first). The cap keeps
    responses bounded — ping_history grows by roughly one row per device per
    minute. Returns a list of Row.
    """
    conn = get_db()
    rows = conn.execute(
        'SELECT id, status, response_time, checked_at '
        'FROM ping_history WHERE device_id = ? '
        'ORDER BY checked_at DESC, id DESC LIMIT ?',
        (device_id, limit),
    ).fetchall()
    conn.close()
    return rows


def get_backups(device_id):
    """Return a device's config_backups, newest first (summary only).

    Selects id, created_at and length(config_text) AS size — NOT the full
    config_text, so a backup listing stays small. Returns a list of Row.
    """
    conn = get_db()
    rows = conn.execute(
        'SELECT id, created_at, length(config_text) AS size '
        'FROM config_backups WHERE device_id = ? '
        'ORDER BY created_at DESC, id DESC',
        (device_id,),
    ).fetchall()
    conn.close()
    return rows


def get_backup(device_id, backup_id):
    """Return one config backup scoped to BOTH device_id and backup_id.

    Scoping to the device id means another device's backup cannot be read by
    guessing the backup id. Selects id, created_at and the full config_text.
    Returns a Row, or None if not found.
    """
    conn = get_db()
    row = conn.execute(
        'SELECT id, created_at, config_text '
        'FROM config_backups WHERE id = ? AND device_id = ?',
        (backup_id, device_id),
    ).fetchone()
    conn.close()
    return row


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
                '',  # Enter real SSH credentials via the Add/Edit Device UI
                'cisco_xe',
            ),
        )
        conn.commit()
    conn.close()
