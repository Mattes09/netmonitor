from flask import Flask, flash, redirect, render_template, request, url_for

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
# Startup
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    seed_devices()
    start_monitor()
    app.run(debug=True, use_reloader=False)
