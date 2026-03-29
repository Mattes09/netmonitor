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
