# NetMonitor — Code Overview

> Single-file consolidated view of the entire NetMonitor codebase, generated for
> quick review of the main project. Each section below is one source file,
> reproduced verbatim. Generated 2026-06-16.
>
> Excluded: `.gitignore`, the SQLite database (`netmonitor.db`), caches, and
> other non-source artifacts.

## Table of Contents

**Python**
- [config.py](#configpy) — application configuration / constants
- [models.py](#modelspy) — SQLite schema, connection helper, shared queries
- [monitor.py](#monitorpy) — background ping/TCP monitor thread
- [audit.py](#auditpy) — rule-based config compliance engine
- [api.py](#apipy) — read-only JSON API blueprint (`/api/v1`)
- [app.py](#apppy) — Flask routes / web UI
- [wsgi.py](#wsgipy) — WSGI entry point for production servers

**Templates (Jinja2 / Bootstrap 5)**
- [templates/base.html](#templatesbasehtml)
- [templates/dashboard.html](#templatesdashboardhtml)
- [templates/device_detail.html](#templatesdevice_detailhtml)
- [templates/add_device.html](#templatesadd_devicehtml)
- [templates/backup_list.html](#templatesbackup_listhtml)
- [templates/backup_detail.html](#templatesbackup_detailhtml)
- [templates/audit_result.html](#templatesaudit_resulthtml)
- [templates/ssh_output.html](#templatesssh_outputhtml)

**Project meta**
- [requirements.txt](#requirementstxt)
- [README.md](#readmemd)

---

# Python

## config.py

```python
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DATABASE = os.path.join(BASE_DIR, 'netmonitor.db')
PING_INTERVAL = 60  # seconds between monitoring cycles
SECRET_KEY = 'dev-secret-key-change-in-production'
```

---

## models.py

```python
import sqlite3
from config import DATABASE


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def get_all_devices():
    """Return all devices with their latest ping status.

    LEFT JOINs each device to its most recent ping_history row, so devices
    with no ping history are still returned (with a null status). Selects
    every device column (d.*) plus the latest status, response_time and
    checked_at — the shared "list devices" query used by the dashboard and
    the JSON API.
    """
    conn = get_db()
    rows = conn.execute('''
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
        ORDER BY d.name
    ''').fetchall()
    conn.close()
    return rows


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
```

---

## monitor.py

```python
import platform
import re
import socket
import subprocess
import threading
import time

from config import PING_INTERVAL
from models import get_db

_stop_event = threading.Event()
_monitor_thread = None


def ping_host(ip_address):
    """Ping ip_address once. Returns (status, response_time_ms | None)."""
    system = platform.system().lower()
    if system == 'windows':
        cmd = ['ping', '-n', '1', '-w', '2000', ip_address]
    elif system == 'darwin':
        # macOS: -t sets timeout in seconds, no -W confusion
        cmd = ['ping', '-c', '1', '-t', '3', ip_address]
    else:
        # Linux: -W timeout in seconds
        cmd = ['ping', '-c', '1', '-W', '3', ip_address]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            match = re.search(r'time[=<](\d+\.?\d*)\s*ms', result.stdout)
            response_time = float(match.group(1)) if match else None
            return 'online', response_time
        return 'offline', None
    except Exception:
        return 'offline', None


def tcp_check(host, port=22, timeout=5):
    """Attempt a TCP connection to host:port. Returns (success, response_time_ms | None)."""
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.monotonic() - start) * 1000
            return True, round(elapsed, 2)
    except Exception:
        return False, None


def check_host(ip_address):
    """Check host reachability: ICMP ping first, TCP port 22 as fallback.

    Returns (status, response_time_ms | None).
    """
    status, response_time = ping_host(ip_address)
    if status == 'online':
        return status, response_time

    # ICMP failed — fall back to TCP port 22
    print(f'[monitor] ICMP ping failed for {ip_address}, falling back to TCP port 22')
    tcp_ok, tcp_time = tcp_check(ip_address)
    if tcp_ok:
        print(f'[monitor] TCP port 22 reachable for {ip_address} ({tcp_time} ms) — marking online')
        return 'online', tcp_time

    return 'offline', None


def check_all_devices():
    """Ping every device in the database and record the result."""
    conn = get_db()
    devices = conn.execute('SELECT id, ip_address FROM devices').fetchall()
    conn.close()

    for device in devices:
        status, response_time = check_host(device['ip_address'])
        conn = get_db()
        conn.execute(
            'INSERT INTO ping_history (device_id, status, response_time) VALUES (?, ?, ?)',
            (device['id'], status, response_time),
        )
        conn.commit()
        conn.close()


def _monitor_loop():
    while not _stop_event.is_set():
        check_all_devices()
        _stop_event.wait(PING_INTERVAL)


def start_monitor():
    """Start the background monitoring thread (daemon — exits with app)."""
    global _monitor_thread
    _stop_event.clear()
    _monitor_thread = threading.Thread(target=_monitor_loop, daemon=True, name='NetMonitor')
    _monitor_thread.start()


def stop_monitor():
    _stop_event.set()
```

---

## audit.py

```python
"""Rule-based configuration compliance audit engine.

Standalone module — depends only on the Python standard library so it can
be imported by the Flask app or run directly for an offline self-test:

    python audit.py
"""
import re

# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
# check semantics:
#   must_contain     -> pass if the pattern matches anywhere in the config
#   must_not_contain -> pass if the pattern matches nowhere in the config
#
# Patterns are matched with re.MULTILINE so ^ anchors to the start of each
# line — e.g. `^ip http server` must NOT match the line `no ip http server`.

COMPLIANCE_RULES = [
    {
        'id': 'svc_password_encryption',
        'title': 'Service password encryption enabled',
        'category': 'Password security',
        'severity': 'high',
        'check': 'must_contain',
        'pattern': r'^service password-encryption\b',
        'remediation': 'Enable `service password-encryption`.',
    },
    {
        'id': 'enable_secret',
        'title': 'Enable secret configured',
        'category': 'Password security',
        'severity': 'high',
        'check': 'must_contain',
        'pattern': r'^enable secret\b',
        'remediation': 'Use `enable secret` rather than a plaintext password.',
    },
    {
        'id': 'no_enable_password',
        'title': 'No plaintext enable password',
        'category': 'Password security',
        'severity': 'medium',
        'check': 'must_not_contain',
        'pattern': r'^enable password\b',
        'remediation': 'Remove `enable password`; use `enable secret`.',
    },
    {
        'id': 'vty_ssh',
        'title': 'SSH allowed on VTY lines',
        'category': 'Management access',
        'severity': 'high',
        'check': 'must_contain',
        'pattern': r'transport input.*\bssh\b',
        'remediation': 'Allow SSH on VTY lines.',
    },
    {
        'id': 'no_telnet',
        'title': 'Telnet disabled on VTY lines',
        'category': 'Management access',
        'severity': 'high',
        'check': 'must_not_contain',
        'pattern': r'transport input.*\btelnet\b',
        'remediation': 'Disable telnet on VTY lines.',
    },
    {
        'id': 'no_transport_all',
        'title': 'No `transport input all`',
        'category': 'Management access',
        'severity': 'medium',
        'check': 'must_not_contain',
        'pattern': r'transport input\s+all\b',
        'remediation': 'Avoid `transport input all`; specify ssh.',
    },
    {
        'id': 'http_server_disabled',
        'title': 'HTTP server disabled',
        'category': 'Services',
        'severity': 'medium',
        'check': 'must_not_contain',
        'pattern': r'^ip http server\b',
        'remediation': 'Disable the HTTP server (`no ip http server`) or use HTTPS only.',
    },
    {
        'id': 'snmp_no_default_comm',
        'title': 'No default SNMP communities',
        'category': 'Services',
        'severity': 'high',
        'check': 'must_not_contain',
        'pattern': r'snmp-server community\s+(public|private)\b',
        'ignorecase': True,
        'remediation': 'Replace default SNMP communities.',
    },
    {
        'id': 'logging_configured',
        'title': 'Logging destination configured',
        'category': 'Logging & time',
        'severity': 'low',
        'check': 'must_contain',
        'pattern': r'^logging\s+\S+',
        'remediation': 'Configure a syslog/logging destination.',
    },
    {
        'id': 'ntp_configured',
        'title': 'NTP server configured',
        'category': 'Logging & time',
        'severity': 'low',
        'check': 'must_contain',
        'pattern': r'^ntp server\b',
        'remediation': 'Configure an NTP server for accurate timestamps.',
    },
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def _matched_line(config_text, match):
    """Return the full (stripped) config line containing *match*."""
    start = config_text.rfind('\n', 0, match.start()) + 1
    end = config_text.find('\n', match.end())
    if end == -1:
        end = len(config_text)
    return config_text[start:end].strip()


def audit_config(config_text):
    """Run all COMPLIANCE_RULES against *config_text*.

    Returns (results, summary) where results is a list of per-rule dicts
    and summary holds the aggregate counts and compliance score.
    """
    results = []
    for rule in COMPLIANCE_RULES:
        flags = re.MULTILINE
        if rule.get('ignorecase'):
            flags |= re.IGNORECASE
        match = re.search(rule['pattern'], config_text, flags)

        if rule['check'] == 'must_contain':
            status = 'pass' if match else 'fail'
            detail = _matched_line(config_text, match) if match else 'Not found'
        else:  # must_not_contain
            status = 'fail' if match else 'pass'
            detail = _matched_line(config_text, match) if match else 'Not present'

        results.append({
            'id': rule['id'],
            'title': rule['title'],
            'category': rule['category'],
            'severity': rule['severity'],
            'status': status,
            'detail': detail,
            'remediation': rule['remediation'],
        })

    total = len(results)
    passed = sum(1 for r in results if r['status'] == 'pass')
    failed = total - passed
    summary = {
        'total': total,
        'passed': passed,
        'failed': failed,
        'score': round(passed / total * 100) if total else 0,
        'failed_high': sum(1 for r in results if r['status'] == 'fail' and r['severity'] == 'high'),
        'failed_medium': sum(1 for r in results if r['status'] == 'fail' and r['severity'] == 'medium'),
        'failed_low': sum(1 for r in results if r['status'] == 'fail' and r['severity'] == 'low'),
    }
    return results, summary


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

WEAK_SAMPLE = """\
hostname weak-router
!
enable password cisco123
!
snmp-server community PUBLIC RO
ip http server
logging 192.0.2.50
ntp server 192.0.2.10
!
line vty 0 4
 transport input all
 password telnetpass
line vty 5 15
 transport input telnet
!
end
"""

HARDENED_SAMPLE = """\
hostname hardened-router
!
service password-encryption
enable secret 9 $9$abcdefghijklmnop
!
no ip http server
no ip http secure-server
snmp-server community S3cureC0mm RO
logging host 192.0.2.50
ntp server 192.0.2.10
!
line vty 0 4
 transport input ssh
 login local
!
end
"""


def _print_report(name, config_text):
    results, summary = audit_config(config_text)
    print(f'=== {name} ===')
    for r in results:
        mark = 'PASS' if r['status'] == 'pass' else 'FAIL'
        print(f"  [{mark}] {r['severity']:<6} {r['title']:<40} {r['detail']}")
    print(f"  Score: {summary['score']}%  "
          f"({summary['passed']}/{summary['total']} passed, "
          f"failed high={summary['failed_high']} "
          f"medium={summary['failed_medium']} low={summary['failed_low']})")
    print()


if __name__ == '__main__':
    _print_report('Weak sample config', WEAK_SAMPLE)
    _print_report('Hardened sample config', HARDENED_SAMPLE)
```

---

## api.py

```python
from flask import Blueprint, jsonify

from models import get_all_devices

# Read-only JSON API. Mounted under /api/v1 (see app.py).
api = Blueprint('api', __name__, url_prefix='/api/v1')


@api.route('/devices')
def list_devices():
    """Return all devices as a JSON array.

    Online/offline status is derived from the most recent ping_history
    row per device — the same logic the dashboard uses. SSH credentials
    (ssh_username / ssh_password) are deliberately excluded.
    """
    rows = get_all_devices()

    devices = [
        {
            'id': row['id'],
            'name': row['name'],
            'address': row['ip_address'],
            'netmiko_device_type': row['netmiko_device_type'],
            'status': row['status'],
        }
        for row in rows
    ]
    return jsonify(devices)
```

---

## app.py

```python
from flask import Flask, flash, redirect, render_template, request, url_for
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

from api import api as api_blueprint
from audit import audit_config
from config import SECRET_KEY
from models import get_all_devices, get_db, init_db, seed_devices
from monitor import check_host, ping_host, start_monitor

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.register_blueprint(api_blueprint)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route('/')
def dashboard():
    devices = get_all_devices()
    return render_template('dashboard.html', devices=devices)


# ---------------------------------------------------------------------------
# Device detail
# ---------------------------------------------------------------------------

@app.route('/device/<int:device_id>')
def device_detail(device_id):
    conn = get_db()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    if not device:
        conn.close()
        flash('Device not found.', 'danger')
        return redirect(url_for('dashboard'))

    history = conn.execute('''
        SELECT * FROM ping_history
        WHERE device_id = ?
        ORDER BY checked_at DESC
        LIMIT 100
    ''', (device_id,)).fetchall()

    uptime = None
    if history:
        online_count = sum(1 for r in history if r['status'] == 'online')
        uptime = round(online_count / len(history) * 100, 1)

    conn.close()
    return render_template('device_detail.html', device=device, history=history, uptime=uptime)


# ---------------------------------------------------------------------------
# Add device
# ---------------------------------------------------------------------------

@app.route('/device/add', methods=['GET', 'POST'])
def add_device():
    if request.method == 'POST':
        name         = request.form.get('name', '').strip()
        ip_address   = request.form.get('ip_address', '').strip()
        device_type  = request.form.get('device_type', 'Unknown').strip() or 'Unknown'
        ssh_username = request.form.get('ssh_username', '').strip() or None
        ssh_password = request.form.get('ssh_password', '').strip() or None

        if not name or not ip_address:
            flash('Device name and IP address are required.', 'danger')
            return render_template('add_device.html')

        conn = get_db()
        try:
            conn.execute(
                'INSERT INTO devices (name, ip_address, device_type, ssh_username, ssh_password) '
                'VALUES (?, ?, ?, ?, ?)',
                (name, ip_address, device_type, ssh_username, ssh_password),
            )
            conn.commit()
            flash(f'Device "{name}" added successfully.', 'success')
            return redirect(url_for('dashboard'))
        except Exception:
            flash('Could not add device — IP address may already exist.', 'danger')
            return render_template('add_device.html')
        finally:
            conn.close()

    return render_template('add_device.html')


# ---------------------------------------------------------------------------
# Delete device
# ---------------------------------------------------------------------------

@app.route('/device/<int:device_id>/delete', methods=['POST'])
def delete_device(device_id):
    conn = get_db()
    device = conn.execute('SELECT name FROM devices WHERE id = ?', (device_id,)).fetchone()
    if device:
        conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
        conn.commit()
        flash(f'Device "{device["name"]}" removed.', 'success')
    conn.close()
    return redirect(url_for('dashboard'))


# ---------------------------------------------------------------------------
# Manual ping check
# ---------------------------------------------------------------------------

@app.route('/device/<int:device_id>/check', methods=['POST'])
def check_device(device_id):
    conn = get_db()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    conn.close()

    if device:
        status, response_time = check_host(device['ip_address'])
        conn = get_db()
        conn.execute(
            'INSERT INTO ping_history (device_id, status, response_time) VALUES (?, ?, ?)',
            (device_id, status, response_time),
        )
        conn.commit()
        conn.close()
        level = 'success' if status == 'online' else 'warning'
        rt_str = f' — {response_time} ms' if response_time is not None else ''
        flash(f'{device["name"]} is <strong>{status}</strong>{rt_str}', level)

    return redirect(request.referrer or url_for('dashboard'))


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def _get_device_or_404(device_id):
    conn = get_db()
    device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    conn.close()
    return device


def _ssh_connect(device):
    """Return a Netmiko ConnectHandler for *device*, or raise on failure."""
    return ConnectHandler(
        device_type=device['netmiko_device_type'],
        host=device['ip_address'],
        username=device['ssh_username'],
        password=device['ssh_password'],
    )


# ---------------------------------------------------------------------------
# SSH: show version
# ---------------------------------------------------------------------------

@app.route('/device/<int:device_id>/connect', methods=['POST'])
def device_connect(device_id):
    device = _get_device_or_404(device_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('dashboard'))

    if not device['ssh_username'] or not device['netmiko_device_type']:
        flash('This device has no SSH credentials configured.', 'warning')
        return redirect(url_for('device_detail', device_id=device_id))

    try:
        with _ssh_connect(device) as conn:
            output = conn.send_command('show version')
    except NetmikoAuthenticationException:
        flash('SSH authentication failed — check credentials.', 'danger')
        return redirect(url_for('device_detail', device_id=device_id))
    except NetmikoTimeoutException:
        flash('SSH connection timed out — device may be unreachable.', 'danger')
        return redirect(url_for('device_detail', device_id=device_id))
    except Exception as exc:
        flash(f'SSH error: {exc}', 'danger')
        return redirect(url_for('device_detail', device_id=device_id))

    return render_template('ssh_output.html', device=device, command='show version', output=output)


# ---------------------------------------------------------------------------
# SSH: backup running-config
# ---------------------------------------------------------------------------

@app.route('/device/<int:device_id>/backup', methods=['POST'])
def device_backup(device_id):
    device = _get_device_or_404(device_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('dashboard'))

    if not device['ssh_username'] or not device['netmiko_device_type']:
        flash('This device has no SSH credentials configured.', 'warning')
        return redirect(url_for('device_detail', device_id=device_id))

    try:
        with _ssh_connect(device) as conn:
            config_text = conn.send_command('show running-config')
    except NetmikoAuthenticationException:
        flash('SSH authentication failed — check credentials.', 'danger')
        return redirect(url_for('device_detail', device_id=device_id))
    except NetmikoTimeoutException:
        flash('SSH connection timed out — device may be unreachable.', 'danger')
        return redirect(url_for('device_detail', device_id=device_id))
    except Exception as exc:
        flash(f'SSH error: {exc}', 'danger')
        return redirect(url_for('device_detail', device_id=device_id))

    db = get_db()
    cursor = db.execute(
        'INSERT INTO config_backups (device_id, config_text) VALUES (?, ?)',
        (device_id, config_text),
    )
    db.commit()
    backup_id = cursor.lastrowid
    backup = db.execute('SELECT * FROM config_backups WHERE id = ?', (backup_id,)).fetchone()
    db.close()

    flash(f'Config backup saved successfully.', 'success')
    return render_template('backup_detail.html', device=device, backup=backup)


# ---------------------------------------------------------------------------
# Backup list & detail
# ---------------------------------------------------------------------------

@app.route('/device/<int:device_id>/backups')
def device_backups(device_id):
    db = get_db()
    device = db.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    if not device:
        db.close()
        flash('Device not found.', 'danger')
        return redirect(url_for('dashboard'))

    backups = db.execute(
        'SELECT id, device_id, created_at, length(config_text) AS size '
        'FROM config_backups WHERE device_id = ? ORDER BY created_at DESC',
        (device_id,),
    ).fetchall()
    db.close()
    return render_template('backup_list.html', device=device, backups=backups)


@app.route('/device/<int:device_id>/backups/<int:backup_id>')
def backup_detail(device_id, backup_id):
    db = get_db()
    device = db.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    backup = db.execute(
        'SELECT * FROM config_backups WHERE id = ? AND device_id = ?',
        (backup_id, device_id),
    ).fetchone()
    db.close()

    if not device or not backup:
        flash('Backup not found.', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('backup_detail.html', device=device, backup=backup)


# ---------------------------------------------------------------------------
# Compliance audit (latest config backup)
# ---------------------------------------------------------------------------

@app.route('/device/<int:device_id>/audit')
def device_audit(device_id):
    db = get_db()
    device = db.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    if not device:
        db.close()
        flash('Device not found.', 'danger')
        return redirect(url_for('dashboard'))

    backup = db.execute(
        'SELECT * FROM config_backups WHERE device_id = ? '
        'ORDER BY created_at DESC, id DESC LIMIT 1',
        (device_id,),
    ).fetchone()
    db.close()

    if not backup:
        flash('Capture a configuration backup before running an audit.', 'warning')
        return redirect(url_for('device_detail', device_id=device_id))

    results, summary = audit_config(backup['config_text'])
    return render_template(
        'audit_result.html',
        device=device, backup=backup, results=results, summary=summary,
    )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    seed_devices()
    start_monitor()
    app.run(debug=True, use_reloader=False)
```

---

## wsgi.py

```python
from app import app
from models import init_db, seed_devices
from monitor import start_monitor

init_db()
seed_devices()
start_monitor()

if __name__ == '__main__':
    app.run()
```

---

# Templates (Jinja2 / Bootstrap 5)

## templates/base.html

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NetMonitor — {% block title %}Dashboard{% endblock %}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
  <style>
    body { background-color: #f4f6f9; }
    .navbar-brand { font-weight: 700; letter-spacing: .5px; }
    .status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
    .table td, .table th { vertical-align: middle; }
    .card { border: none; }
    .ping-badge { min-width: 80px; }
  </style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow-sm">
  <div class="container">
    <a class="navbar-brand" href="/">
      <i class="bi bi-hdd-network me-2"></i>NetMonitor
    </a>
    <div class="navbar-nav ms-auto">
      <a class="nav-link {% if request.endpoint == 'dashboard' %}active{% endif %}" href="/">
        <i class="bi bi-speedometer2 me-1"></i>Dashboard
      </a>
      <a class="nav-link {% if request.endpoint == 'add_device' %}active{% endif %}" href="/device/add">
        <i class="bi bi-plus-circle me-1"></i>Add Device
      </a>
    </div>
  </div>
</nav>

<div class="container mt-4 mb-5">

  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
          {{ message | safe }}
          <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  {% block content %}{% endblock %}

</div>

<footer class="text-center text-muted py-3 border-top small">
  NetMonitor &mdash; Bachelor Thesis 2026 &mdash; Matej Madzin, Unicorn University
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

---

## templates/dashboard.html

```html
{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
  <div>
    <h2 class="mb-0"><i class="bi bi-speedometer2 me-2"></i>Network Dashboard</h2>
    <small class="text-muted">Live status of all monitored devices (auto-refresh every 60 s)</small>
  </div>
  <a href="/device/add" class="btn btn-primary">
    <i class="bi bi-plus-lg me-1"></i>Add Device
  </a>
</div>

{% set online_count  = devices | selectattr('status', 'equalto', 'online')  | list | length %}
{% set offline_count = devices | selectattr('status', 'equalto', 'offline') | list | length %}
{% set unknown_count = devices | length - online_count - offline_count %}

<div class="row g-3 mb-4">
  <div class="col-sm-4">
    <div class="card shadow-sm text-center py-3">
      <div class="fs-1 text-success fw-bold">{{ online_count }}</div>
      <div class="text-muted small">Online</div>
    </div>
  </div>
  <div class="col-sm-4">
    <div class="card shadow-sm text-center py-3">
      <div class="fs-1 text-danger fw-bold">{{ offline_count }}</div>
      <div class="text-muted small">Offline</div>
    </div>
  </div>
  <div class="col-sm-4">
    <div class="card shadow-sm text-center py-3">
      <div class="fs-1 text-secondary fw-bold">{{ devices | length }}</div>
      <div class="text-muted small">Total Devices</div>
    </div>
  </div>
</div>

<div class="card shadow-sm">
  <div class="card-body p-0">
    <table class="table table-hover mb-0">
      <thead class="table-dark">
        <tr>
          <th>#</th>
          <th>Device Name</th>
          <th>IP Address</th>
          <th>Type</th>
          <th>Status</th>
          <th>Response Time</th>
          <th>Last Checked</th>
          <th class="text-end">Actions</th>
        </tr>
      </thead>
      <tbody>
        {% for device in devices %}
        <tr>
          <td class="text-muted">{{ device.id }}</td>
          <td>
            <a href="/device/{{ device.id }}" class="text-decoration-none fw-semibold">
              {{ device.name }}
            </a>
          </td>
          <td><code>{{ device.ip_address }}</code></td>
          <td><span class="badge bg-secondary">{{ device.device_type }}</span></td>
          <td>
            {% if device.status == 'online' %}
              <span class="badge bg-success ping-badge"><i class="bi bi-circle-fill me-1" style="font-size:.5rem"></i>Online</span>
            {% elif device.status == 'offline' %}
              <span class="badge bg-danger ping-badge"><i class="bi bi-circle-fill me-1" style="font-size:.5rem"></i>Offline</span>
            {% else %}
              <span class="badge bg-warning text-dark ping-badge"><i class="bi bi-circle-fill me-1" style="font-size:.5rem"></i>Unknown</span>
            {% endif %}
          </td>
          <td>
            {% if device.response_time %}
              <span class="{% if device.response_time < 50 %}text-success{% elif device.response_time < 200 %}text-warning{% else %}text-danger{% endif %}">
                {{ "%.1f"|format(device.response_time) }} ms
              </span>
            {% else %}
              <span class="text-muted">—</span>
            {% endif %}
          </td>
          <td class="text-muted small">
            {{ device.last_checked if device.last_checked else 'Never' }}
          </td>
          <td class="text-end">
            <form method="post" action="/device/{{ device.id }}/check" class="d-inline">
              <button class="btn btn-sm btn-outline-primary" title="Ping now">
                <i class="bi bi-activity"></i>
              </button>
            </form>
            <a href="/device/{{ device.id }}" class="btn btn-sm btn-outline-secondary" title="History">
              <i class="bi bi-clock-history"></i>
            </a>
            {% if device.ssh_username %}
            <form method="post" action="/device/{{ device.id }}/connect" class="d-inline">
              <button class="btn btn-sm btn-outline-info" title="SSH: show version">
                <i class="bi bi-terminal"></i>
              </button>
            </form>
            <form method="post" action="/device/{{ device.id }}/backup" class="d-inline">
              <button class="btn btn-sm btn-outline-warning" title="Backup running-config">
                <i class="bi bi-floppy"></i>
              </button>
            </form>
            {% endif %}
            <form method="post" action="/device/{{ device.id }}/delete" class="d-inline"
                  onsubmit="return confirm('Delete {{ device.name }}?')">
              <button class="btn btn-sm btn-outline-danger" title="Delete">
                <i class="bi bi-trash"></i>
              </button>
            </form>
          </td>
        </tr>
        {% else %}
        <tr>
          <td colspan="8" class="text-center text-muted py-4">
            No devices yet. <a href="/device/add">Add one now.</a>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>

<p class="text-muted mt-3 small">
  <i class="bi bi-info-circle me-1"></i>
  Background monitor checks all devices every 60 seconds. Click
  <i class="bi bi-activity"></i> to trigger an immediate check.
</p>

<script>
  // Auto-refresh the page every 60 seconds
  setTimeout(() => location.reload(), 60000);

  // Ping button loading state
  document.querySelectorAll('form[action$="/check"]').forEach(form => {
    form.addEventListener('submit', function () {
      const btn = this.querySelector('button');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Pinging…';
    });
  });
</script>
{% endblock %}
```

---

## templates/device_detail.html

```html
{% extends "base.html" %}
{% block title %}{{ device.name }}{% endblock %}

{% block content %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="/">Dashboard</a></li>
    <li class="breadcrumb-item active">{{ device.name }}</li>
  </ol>
</nav>

<!-- Device header card -->
<div class="card shadow-sm mb-4">
  <div class="card-body">
    <div class="d-flex justify-content-between align-items-start flex-wrap gap-3">
      <div>
        <h3 class="mb-1">
          <i class="bi bi-hdd-network me-2 text-primary"></i>{{ device.name }}
        </h3>
        <p class="text-muted mb-0">
          <code>{{ device.ip_address }}</code>
          &nbsp;&bull;&nbsp;
          <span class="badge bg-secondary">{{ device.device_type }}</span>
          {% if device.ssh_username %}
            &nbsp;&bull;&nbsp;
            <span class="text-muted small"><i class="bi bi-terminal me-1"></i>SSH: {{ device.ssh_username }}</span>
          {% endif %}
        </p>
      </div>

      <div class="d-flex gap-2 align-items-center">
        {% if history %}
          {% set latest = history[0] %}
          {% if latest.status == 'online' %}
            <span class="badge bg-success fs-6 px-3 py-2"><i class="bi bi-circle-fill me-1" style="font-size:.5rem"></i>Online</span>
          {% elif latest.status == 'offline' %}
            <span class="badge bg-danger fs-6 px-3 py-2"><i class="bi bi-circle-fill me-1" style="font-size:.5rem"></i>Offline</span>
          {% endif %}
        {% else %}
          <span class="badge bg-warning text-dark fs-6 px-3 py-2">Unknown</span>
        {% endif %}

        <form method="post" action="/device/{{ device.id }}/check">
          <button class="btn btn-primary">
            <i class="bi bi-activity me-1"></i>Check Now
          </button>
        </form>

        {% if device.ssh_username %}
        <form method="post" action="/device/{{ device.id }}/connect">
          <button class="btn btn-info text-white">
            <i class="bi bi-terminal me-1"></i>Connect
          </button>
        </form>
        <form method="post" action="/device/{{ device.id }}/backup">
          <button class="btn btn-warning">
            <i class="bi bi-floppy me-1"></i>Backup Config
          </button>
        </form>
        <a href="/device/{{ device.id }}/backups" class="btn btn-outline-secondary">
          <i class="bi bi-archive me-1"></i>Backups
        </a>
        <a href="/device/{{ device.id }}/audit" class="btn btn-success">
          <i class="bi bi-shield-check me-1"></i>Run Compliance Audit
        </a>
        {% endif %}

        <form method="post" action="/device/{{ device.id }}/delete"
              onsubmit="return confirm('Delete {{ device.name }}?')">
          <button class="btn btn-outline-danger">
            <i class="bi bi-trash me-1"></i>Delete
          </button>
        </form>
      </div>
    </div>
  </div>
</div>

<!-- Stats row -->
{% if history %}
<div class="row g-3 mb-4">
  <div class="col-sm-3">
    <div class="card shadow-sm text-center py-3">
      <div class="fs-3 fw-bold {% if uptime >= 90 %}text-success{% elif uptime >= 50 %}text-warning{% else %}text-danger{% endif %}">
        {{ uptime }}%
      </div>
      <div class="text-muted small">Uptime (last {{ history|length }} checks)</div>
    </div>
  </div>
  {% set rt_values = history | selectattr('response_time') | map(attribute='response_time') | list %}
  {% if rt_values %}
  <div class="col-sm-3">
    <div class="card shadow-sm text-center py-3">
      <div class="fs-3 fw-bold text-primary">{{ "%.1f"|format(rt_values | min) }} ms</div>
      <div class="text-muted small">Best Response</div>
    </div>
  </div>
  <div class="col-sm-3">
    <div class="card shadow-sm text-center py-3">
      <div class="fs-3 fw-bold text-primary">
        {{ "%.1f"|format((rt_values | sum) / (rt_values | length)) }} ms
      </div>
      <div class="text-muted small">Avg Response</div>
    </div>
  </div>
  <div class="col-sm-3">
    <div class="card shadow-sm text-center py-3">
      <div class="fs-3 fw-bold text-primary">{{ "%.1f"|format(rt_values | max) }} ms</div>
      <div class="text-muted small">Worst Response</div>
    </div>
  </div>
  {% endif %}
</div>
{% endif %}

<!-- Ping history table -->
<div class="card shadow-sm">
  <div class="card-header bg-white d-flex justify-content-between align-items-center">
    <strong><i class="bi bi-clock-history me-2"></i>Ping History</strong>
    <span class="badge bg-secondary">Last {{ history | length }} records</span>
  </div>
  <div class="card-body p-0">
    <table class="table table-hover table-sm mb-0">
      <thead class="table-light">
        <tr>
          <th>#</th>
          <th>Status</th>
          <th>Response Time</th>
          <th>Checked At</th>
        </tr>
      </thead>
      <tbody>
        {% for record in history %}
        <tr>
          <td class="text-muted">{{ loop.index }}</td>
          <td>
            {% if record.status == 'online' %}
              <span class="badge bg-success">Online</span>
            {% else %}
              <span class="badge bg-danger">Offline</span>
            {% endif %}
          </td>
          <td>
            {% if record.response_time %}
              <span class="{% if record.response_time < 50 %}text-success{% elif record.response_time < 200 %}text-warning{% else %}text-danger{% endif %}">
                {{ "%.1f"|format(record.response_time) }} ms
              </span>
            {% else %}
              <span class="text-muted">—</span>
            {% endif %}
          </td>
          <td class="text-muted small">{{ record.checked_at }}</td>
        </tr>
        {% else %}
        <tr>
          <td colspan="4" class="text-center text-muted py-4">
            No history yet. Click <strong>Check Now</strong> above to run the first ping.
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
```

---

## templates/add_device.html

```html
{% extends "base.html" %}
{% block title %}Add Device{% endblock %}

{% block content %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="/">Dashboard</a></li>
    <li class="breadcrumb-item active">Add Device</li>
  </ol>
</nav>

<div class="row justify-content-center">
  <div class="col-lg-6">
    <div class="card shadow-sm">
      <div class="card-header bg-white">
        <h5 class="mb-0"><i class="bi bi-plus-circle me-2 text-primary"></i>Add New Device</h5>
      </div>
      <div class="card-body">
        <form method="post" action="/device/add" novalidate>

          <div class="mb-3">
            <label for="name" class="form-label fw-semibold">Device Name <span class="text-danger">*</span></label>
            <input type="text" class="form-control" id="name" name="name"
                   placeholder="e.g. Core Switch 1" required>
          </div>

          <div class="mb-3">
            <label for="ip_address" class="form-label fw-semibold">IP Address <span class="text-danger">*</span></label>
            <input type="text" class="form-control" id="ip_address" name="ip_address"
                   placeholder="e.g. 192.168.1.1" required>
          </div>

          <div class="mb-3">
            <label for="device_type" class="form-label fw-semibold">Device Type</label>
            <select class="form-select" id="device_type" name="device_type">
              <option value="Unknown">Unknown</option>
              <option value="Router">Router</option>
              <option value="Switch">Switch</option>
              <option value="Firewall">Firewall</option>
              <option value="Server">Server</option>
              <option value="Virtual Machine">Virtual Machine</option>
              <option value="DNS Server">DNS Server</option>
              <option value="Access Point">Access Point</option>
              <option value="Other">Other</option>
            </select>
          </div>

          <hr class="my-3">
          <p class="text-muted small mb-3">
            <i class="bi bi-lock me-1"></i>SSH credentials are optional — used for future configuration backup features.
          </p>

          <div class="mb-3">
            <label for="ssh_username" class="form-label fw-semibold">SSH Username</label>
            <input type="text" class="form-control" id="ssh_username" name="ssh_username"
                   placeholder="admin" autocomplete="off">
          </div>

          <div class="mb-4">
            <label for="ssh_password" class="form-label fw-semibold">SSH Password</label>
            <input type="password" class="form-control" id="ssh_password" name="ssh_password"
                   autocomplete="new-password">
          </div>

          <div class="d-flex gap-2">
            <button type="submit" class="btn btn-primary">
              <i class="bi bi-plus-lg me-1"></i>Add Device
            </button>
            <a href="/" class="btn btn-outline-secondary">Cancel</a>
          </div>

        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}
```

---

## templates/backup_list.html

```html
{% extends "base.html" %}
{% block title %}Backups — {{ device.name }}{% endblock %}

{% block content %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="/">Dashboard</a></li>
    <li class="breadcrumb-item"><a href="/device/{{ device.id }}">{{ device.name }}</a></li>
    <li class="breadcrumb-item active">Config Backups</li>
  </ol>
</nav>

<div class="d-flex justify-content-between align-items-center mb-4">
  <div>
    <h4 class="mb-0"><i class="bi bi-floppy me-2"></i>Config Backups</h4>
    <small class="text-muted">
      {{ device.name }} &mdash; <code>{{ device.ip_address }}</code>
    </small>
  </div>
  <form method="post" action="/device/{{ device.id }}/backup">
    <button class="btn btn-warning">
      <i class="bi bi-floppy me-1"></i>Take New Backup
    </button>
  </form>
</div>

<div class="card shadow-sm">
  <div class="card-body p-0">
    <table class="table table-hover mb-0">
      <thead class="table-dark">
        <tr>
          <th>#</th>
          <th>Captured At</th>
          <th>Size</th>
          <th class="text-end">Actions</th>
        </tr>
      </thead>
      <tbody>
        {% for b in backups %}
        <tr>
          <td class="text-muted">{{ b.id }}</td>
          <td>{{ b.created_at }}</td>
          <td>{{ "%.1f"|format(b.size / 1024) }} KB</td>
          <td class="text-end">
            <a href="/device/{{ device.id }}/backups/{{ b.id }}" class="btn btn-sm btn-outline-secondary">
              <i class="bi bi-eye me-1"></i>View
            </a>
          </td>
        </tr>
        {% else %}
        <tr>
          <td colspan="4" class="text-center text-muted py-4">
            No backups yet. Click <strong>Take New Backup</strong> to capture the running config.
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
```

---

## templates/backup_detail.html

```html
{% extends "base.html" %}
{% block title %}Backup {{ backup.id }} — {{ device.name }}{% endblock %}

{% block content %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="/">Dashboard</a></li>
    <li class="breadcrumb-item"><a href="/device/{{ device.id }}">{{ device.name }}</a></li>
    <li class="breadcrumb-item"><a href="/device/{{ device.id }}/backups">Backups</a></li>
    <li class="breadcrumb-item active">#{{ backup.id }}</li>
  </ol>
</nav>

<div class="card shadow-sm mb-4">
  <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
    <span>
      <i class="bi bi-floppy me-2"></i>Running Config Backup
      &nbsp;&mdash;&nbsp;{{ device.name }}
      <span class="badge bg-secondary ms-2">{{ device.ip_address }}</span>
      <span class="badge bg-info text-dark ms-1">{{ backup.created_at }}</span>
    </span>
    <div class="d-flex gap-2">
      <a href="/device/{{ device.id }}/backups" class="btn btn-sm btn-outline-light">
        <i class="bi bi-list me-1"></i>All Backups
      </a>
      <a href="/device/{{ device.id }}" class="btn btn-sm btn-outline-light">
        <i class="bi bi-arrow-left me-1"></i>Device
      </a>
    </div>
  </div>
  <div class="card-body p-0">
    <pre class="m-0 p-3" style="background:#1e1e1e;color:#d4d4d4;font-size:.85rem;white-space:pre-wrap;word-break:break-all;max-height:70vh;overflow-y:auto;">{{ backup.config_text }}</pre>
  </div>
</div>
{% endblock %}
```

---

## templates/audit_result.html

```html
{% extends "base.html" %}
{% block title %}Compliance Audit — {{ device.name }}{% endblock %}

{% block content %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="/">Dashboard</a></li>
    <li class="breadcrumb-item"><a href="/device/{{ device.id }}">{{ device.name }}</a></li>
    <li class="breadcrumb-item active">Compliance Audit</li>
  </ol>
</nav>

<!-- Summary card -->
<div class="card shadow-sm mb-4">
  <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
    <span>
      <i class="bi bi-shield-check me-2"></i>Compliance Audit
      &nbsp;&mdash;&nbsp;{{ device.name }}
      <span class="badge bg-secondary ms-2">{{ device.ip_address }}</span>
      <span class="badge bg-info text-dark ms-1">Backup: {{ backup.created_at }}</span>
    </span>
    <div class="d-flex gap-2">
      <a href="/device/{{ device.id }}/backups" class="btn btn-sm btn-outline-light">
        <i class="bi bi-archive me-1"></i>Backups
      </a>
      <a href="/device/{{ device.id }}" class="btn btn-sm btn-outline-light">
        <i class="bi bi-arrow-left me-1"></i>Device
      </a>
    </div>
  </div>
  <div class="card-body">
    <div class="d-flex justify-content-between align-items-center flex-wrap gap-3 mb-2">
      <div>
        <span class="fs-3 fw-bold {% if summary.score >= 90 %}text-success{% elif summary.score >= 50 %}text-warning{% else %}text-danger{% endif %}">
          {{ summary.score }}%
        </span>
        <span class="text-muted">compliant ({{ summary.passed }}/{{ summary.total }} checks passed)</span>
      </div>
      <div class="d-flex gap-2">
        {% if summary.failed_high %}
          <span class="badge bg-danger fs-6">{{ summary.failed_high }} high</span>
        {% endif %}
        {% if summary.failed_medium %}
          <span class="badge bg-warning text-dark fs-6">{{ summary.failed_medium }} medium</span>
        {% endif %}
        {% if summary.failed_low %}
          <span class="badge bg-secondary fs-6">{{ summary.failed_low }} low</span>
        {% endif %}
        {% if not summary.failed %}
          <span class="badge bg-success fs-6"><i class="bi bi-check-circle me-1"></i>All checks passed</span>
        {% endif %}
      </div>
    </div>
    <div class="progress" style="height: 1.5rem;">
      <div class="progress-bar {% if summary.score >= 90 %}bg-success{% elif summary.score >= 50 %}bg-warning{% else %}bg-danger{% endif %}"
           role="progressbar" style="width: {{ summary.score }}%;"
           aria-valuenow="{{ summary.score }}" aria-valuemin="0" aria-valuemax="100">
        {{ summary.score }}%
      </div>
    </div>
  </div>
</div>

<!-- Results table -->
<div class="card shadow-sm">
  <div class="card-header bg-white d-flex justify-content-between align-items-center">
    <strong><i class="bi bi-list-check me-2"></i>Rule Results</strong>
    <span class="badge bg-secondary">{{ summary.total }} rules</span>
  </div>
  <div class="card-body p-0">
    <table class="table table-hover table-sm mb-0 align-middle">
      <thead class="table-light">
        <tr>
          <th>Rule</th>
          <th>Category</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Detail</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {% for r in results %}
        <tr>
          <td>{{ r.title }}</td>
          <td class="text-muted small">{{ r.category }}</td>
          <td>
            {% if r.severity == 'high' %}
              <span class="badge bg-danger">High</span>
            {% elif r.severity == 'medium' %}
              <span class="badge bg-warning text-dark">Medium</span>
            {% else %}
              <span class="badge bg-secondary">Low</span>
            {% endif %}
          </td>
          <td>
            {% if r.status == 'pass' %}
              <span class="badge bg-success">Pass</span>
            {% else %}
              <span class="badge bg-danger">Fail</span>
            {% endif %}
          </td>
          <td><code class="small">{{ r.detail }}</code></td>
          <td class="text-muted small">{{ r.remediation }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
```

---

## templates/ssh_output.html

```html
{% extends "base.html" %}
{% block title %}{{ command }} — {{ device.name }}{% endblock %}

{% block content %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="/">Dashboard</a></li>
    <li class="breadcrumb-item"><a href="/device/{{ device.id }}">{{ device.name }}</a></li>
    <li class="breadcrumb-item active">SSH Output</li>
  </ol>
</nav>

<div class="card shadow-sm mb-4">
  <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
    <span>
      <i class="bi bi-terminal me-2"></i>
      <code class="text-warning">{{ command }}</code>
      &nbsp;&mdash;&nbsp;{{ device.name }}
      <span class="badge bg-secondary ms-2">{{ device.ip_address }}</span>
    </span>
    <div class="d-flex gap-2">
      <form method="post" action="/device/{{ device.id }}/backup">
        <button class="btn btn-sm btn-warning">
          <i class="bi bi-floppy me-1"></i>Backup Config
        </button>
      </form>
      <a href="/device/{{ device.id }}" class="btn btn-sm btn-outline-light">
        <i class="bi bi-arrow-left me-1"></i>Back
      </a>
    </div>
  </div>
  <div class="card-body p-0">
    <pre class="m-0 p-3" style="background:#1e1e1e;color:#d4d4d4;font-size:.85rem;white-space:pre-wrap;word-break:break-all;max-height:70vh;overflow-y:auto;">{{ output }}</pre>
  </div>
</div>
{% endblock %}
```

---

# Project meta

## requirements.txt

```
# NetMonitor - Python Dependencies
# Install with: pip install -r requirements.txt

Flask==3.1.0
netmiko
```

---

## README.md

```markdown
# NetMonitor - Network Monitoring & Configuration Audit Tool
A web application for automated network device monitoring, configuration backup, and complience auditing.

## About

**NetMonitor** is a ligthweight, modular web-based tool designed to simplify network infrastructure management. It provides:

- **Active Monitoring** –Real-time availability checks of network devices via ICMP/TCP
- **Configuration Backup** –Automated SSH-based retrieval and versioning of device configurations
- **Compliance Audit** –Validation of configurations against predefined secuirty rules

This project is developed as a Bachelor Thesis at Unicorn Universty, Software Development program.

## Tech Stack

 Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Network Automation | Netmiko (SSH) |
| Database | SQLite |
| Frontend | HTML, CSS (Bootstrap), JavaScript |
| Testing Environment | Cisco DevNet Sandbox |

## Status

🚧 **Under Development** — Phase 0: Foundation & Setup

## Author

**Matej Madzin**
Software Development, Unicorn University
Bachelor Thesis 2026
Supervisor: Ing. Ivo Milota
```
