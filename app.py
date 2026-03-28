from flask import Flask, flash, redirect, render_template, request, url_for
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

from config import SECRET_KEY
from models import get_db, init_db, seed_devices
from monitor import ping_host, start_monitor

app = Flask(__name__)
app.secret_key = SECRET_KEY


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route('/')
def dashboard():
    conn = get_db()
    devices = conn.execute('''
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
        status, response_time = ping_host(device['ip_address'])
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
# Startup
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    seed_devices()
    start_monitor()
    app.run(debug=True, use_reloader=False)
