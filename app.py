from flask import Flask, flash, redirect, render_template, request, url_for
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

from api import api as api_blueprint
from audit import audit_config
from config import SECRET_KEY
from models import create_device, get_all_devices, get_db, get_device, init_db, seed_devices
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
    device = get_device(device_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db()
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
        name                = request.form.get('name', '').strip()
        ip_address          = request.form.get('ip_address', '').strip()
        device_type         = request.form.get('device_type', 'Unknown').strip() or 'Unknown'
        ssh_username        = request.form.get('ssh_username', '').strip() or None
        ssh_password        = request.form.get('ssh_password', '').strip() or None
        netmiko_device_type = request.form.get('netmiko_device_type', '').strip() or None

        if not name or not ip_address:
            flash('Device name and IP address are required.', 'danger')
            return render_template('add_device.html')

        try:
            create_device({
                'name': name,
                'ip_address': ip_address,
                'device_type': device_type,
                'ssh_username': ssh_username,
                'ssh_password': ssh_password,
                'netmiko_device_type': netmiko_device_type,
            })
            flash(f'Device "{name}" added successfully.', 'success')
            return redirect(url_for('dashboard'))
        except Exception:
            flash('Could not add device — IP address may already exist.', 'danger')
            return render_template('add_device.html')

    return render_template('add_device.html')


# ---------------------------------------------------------------------------
# Delete device
# ---------------------------------------------------------------------------

@app.route('/device/<int:device_id>/delete', methods=['POST'])
def delete_device(device_id):
    device = get_device(device_id)
    if device:
        conn = get_db()
        conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
        conn.commit()
        conn.close()
        flash(f'Device "{device["name"]}" removed.', 'success')
    return redirect(url_for('dashboard'))


# ---------------------------------------------------------------------------
# Manual ping check
# ---------------------------------------------------------------------------

@app.route('/device/<int:device_id>/check', methods=['POST'])
def check_device(device_id):
    device = get_device(device_id)

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
    device = get_device(device_id)
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
    device = get_device(device_id)
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
    device = get_device(device_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('dashboard'))

    db = get_db()
    backups = db.execute(
        'SELECT id, device_id, created_at, length(config_text) AS size '
        'FROM config_backups WHERE device_id = ? ORDER BY created_at DESC',
        (device_id,),
    ).fetchall()
    db.close()
    return render_template('backup_list.html', device=device, backups=backups)


@app.route('/device/<int:device_id>/backups/<int:backup_id>')
def backup_detail(device_id, backup_id):
    device = get_device(device_id)
    db = get_db()
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
    device = get_device(device_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('dashboard'))

    db = get_db()
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
