import sqlite3

from flask import Flask, flash, redirect, render_template, request, url_for
from markupsafe import Markup
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

import drift
from api import api as api_blueprint
from audit import audit_config
from config import SECRET_KEY
from models import (
    create_device,
    get_all_devices,
    get_backup,
    get_backups,
    get_db,
    get_device,
    init_db,
    seed_devices,
    update_device,
    validate_device_data,
)
# Aliased: the route view below is also named delete_device, and the route's
# `def` rebinds the module global — without the alias the in-route call would
# resolve to the view itself and recurse infinitely.
from models import delete_device as delete_device_record
from monitor import check_host, start_monitor

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.register_blueprint(api_blueprint)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route('/')
def dashboard():
    sort_key = request.args.get('sort', 'id')
    devices = get_all_devices(sort_key)
    return render_template('dashboard.html', devices=devices, sort_key=sort_key)


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

        data = {
            'name': name,
            'ip_address': ip_address,
            'device_type': device_type,
            'ssh_username': ssh_username,
            'ssh_password': ssh_password,
            'netmiko_device_type': netmiko_device_type,
        }

        errors = validate_device_data(data)
        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('add_device.html', form=data)

        try:
            create_device(data)
            flash(f'Device "{name}" added successfully.', 'success')
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            flash('Could not add device — a device with this IP address already exists.', 'danger')
            return render_template('add_device.html', form=data)
        except Exception:
            flash('Could not add device — an unexpected error occurred.', 'danger')
            return render_template('add_device.html', form=data)

    return render_template('add_device.html', form={})


# ---------------------------------------------------------------------------
# Edit device
# ---------------------------------------------------------------------------

@app.route('/device/<int:device_id>/edit', methods=['GET', 'POST'])
def edit_device(device_id):
    device = get_device(device_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name                = request.form.get('name', '').strip()
        ip_address          = request.form.get('ip_address', '').strip()
        device_type         = request.form.get('device_type', 'Unknown').strip() or 'Unknown'
        ssh_username        = request.form.get('ssh_username', '').strip() or None
        netmiko_device_type = request.form.get('netmiko_device_type', '').strip() or None

        # Blank password field = keep the existing password (form never pre-fills it).
        pw_input = request.form.get('ssh_password', '').strip()
        ssh_password = pw_input if pw_input else device['ssh_password']

        data = {
            'name': name,
            'ip_address': ip_address,
            'device_type': device_type,
            'ssh_username': ssh_username,
            'ssh_password': ssh_password,
            'netmiko_device_type': netmiko_device_type,
        }

        errors = validate_device_data(data)
        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('edit_device.html', device=device, form=data)

        try:
            update_device(device_id, data)
            flash('Device updated successfully.', 'success')
            return redirect(url_for('device_detail', device_id=device_id))
        except sqlite3.IntegrityError:
            flash('Could not update device — a device with this IP address already exists.', 'danger')
            return render_template('edit_device.html', device=device, form=data)
        except Exception:
            flash('Could not update device — an unexpected error occurred.', 'danger')
            return render_template('edit_device.html', device=device, form=data)

    return render_template('edit_device.html', device=device, form=dict(device))


# ---------------------------------------------------------------------------
# Delete device
# ---------------------------------------------------------------------------

@app.route('/device/<int:device_id>/delete', methods=['POST'])
def delete_device(device_id):
    device = get_device(device_id)
    if device:
        delete_device_record(device_id)
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
        # The flash banner no longer trusts raw HTML (see base.html), so this is
        # the one message that opts back into markup deliberately: Markup.format
        # keeps the static <strong> wrapper trusted while escaping every
        # substituted value — including the user-supplied device name.
        flash(Markup('{name} is <strong>{status}</strong>{rt}').format(
            name=device['name'], status=status, rt=rt_str), level)

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

    if not device['ssh_username'] or not device['ssh_password']:
        flash('This device has no SSH credentials configured.', 'warning')
        return redirect(url_for('device_detail', device_id=device_id))
    if not device['netmiko_device_type']:
        flash('This device has no device type set — choose a Netmiko driver to enable SSH.', 'warning')
        return redirect(url_for('device_detail', device_id=device_id))

    try:
        with _ssh_connect(device) as conn:
            output = conn.send_command('show version')
    except NetmikoAuthenticationException:
        flash('SSH authentication failed — check credentials.', 'danger')
        return redirect(url_for('device_detail', device_id=device_id))
    except NetmikoTimeoutException:
        flash('SSH connection failed — no response from the device. It may be offline, unreachable, or refusing the connection.', 'danger')
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

    if not device['ssh_username'] or not device['ssh_password']:
        flash('This device has no SSH credentials configured.', 'warning')
        return redirect(url_for('device_detail', device_id=device_id))
    if not device['netmiko_device_type']:
        flash('This device has no device type set — choose a Netmiko driver to enable SSH.', 'warning')
        return redirect(url_for('device_detail', device_id=device_id))

    try:
        with _ssh_connect(device) as conn:
            config_text = conn.send_command('show running-config')
    except NetmikoAuthenticationException:
        flash('SSH authentication failed — check credentials.', 'danger')
        return redirect(url_for('device_detail', device_id=device_id))
    except NetmikoTimeoutException:
        flash('SSH connection failed — no response from the device. It may be offline, unreachable, or refusing the connection.', 'danger')
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
# Configuration drift (compare two config backups)
# ---------------------------------------------------------------------------

@app.route('/device/<int:device_id>/drift')
def device_drift(device_id):
    """Compare two of a device's stored config backups and show what changed.

    Read-only: it diffs two already-captured backups and never contacts the
    device. ?from=<older id>&to=<newer id> select the pair; both default to the
    two most recent backups when missing or invalid.
    """
    device = get_device(device_id)
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('dashboard'))

    # Summaries only (id, created_at, size) — never the full config_text — to
    # populate the two selectors and compute the defaults.
    backups = get_backups(device_id)
    if len(backups) < 2:
        return render_template(
            'config_drift.html',
            device=device, backups=backups, result=None,
            from_id=None, to_id=None, from_created_at=None, to_created_at=None,
        )

    from_id = request.args.get('from', type=int)
    to_id = request.args.get('to', type=int)

    # get_backup is scoped to BOTH device_id and backup_id, so it returns None
    # for a missing, non-existent or foreign id — that scoping is the security
    # check. Any such id falls back to a default: from = second newest (older),
    # to = newest (newer), so the diff reads older -> newer.
    old_row = get_backup(device_id, from_id)
    if old_row is None:
        from_id = backups[1]['id']
        old_row = get_backup(device_id, from_id)

    new_row = get_backup(device_id, to_id)
    if new_row is None:
        to_id = backups[0]['id']
        new_row = get_backup(device_id, to_id)

    result = drift.compute_drift(old_row['config_text'], new_row['config_text'])
    return render_template(
        'config_drift.html',
        device=device, backups=backups, result=result,
        from_id=from_id, to_id=to_id,
        from_created_at=old_row['created_at'], to_created_at=new_row['created_at'],
    )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    seed_devices()
    start_monitor()
    app.run(debug=True, use_reloader=False)
