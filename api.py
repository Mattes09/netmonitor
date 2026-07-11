import hmac
import os
import sqlite3

from flask import Blueprint, jsonify, request, url_for

from drift import compute_drift
from models import (
    create_device,
    delete_device,
    get_all_devices,
    get_backup,
    get_backups,
    get_device,
    get_ping_history,
    update_device,
    validate_device_data,
)

# JSON CRUD API for devices: list/create/read/update/delete, Bearer-token
# authenticated. Mounted under /api/v1 (see app.py).
api = Blueprint('api', __name__, url_prefix='/api/v1')


@api.before_request
def require_api_key():
    """Reject any /api/v1 request lacking a valid Bearer API key.

    The expected key is read from NETMONITOR_API_KEY (never hardcoded —
    the repo is public). If no key is configured on the server, the API
    fails closed (500) rather than serving requests unprotected.
    """
    expected = os.environ.get('NETMONITOR_API_KEY')
    if not expected:
        return jsonify({'error': 'API key not configured on server'}), 500

    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'unauthorized'}), 401, {'WWW-Authenticate': 'Bearer'}

    provided = auth[7:].strip()
    if not hmac.compare_digest(provided.encode('utf-8'), expected.encode('utf-8')):
        return jsonify({'error': 'unauthorized'}), 401, {'WWW-Authenticate': 'Bearer'}


def device_to_json(row):
    """Serialize a device row to its public JSON shape.

    This is the single definition of the device JSON shape: SSH credentials
    (ssh_username / ssh_password) are excluded here and nowhere else. The
    single-device row from get_device has no joined status column, so status
    is accessed safely.
    """
    status = row['status'] if 'status' in row.keys() else None
    return {
        'id': row['id'],
        'name': row['name'],
        'address': row['ip_address'],
        'netmiko_device_type': row['netmiko_device_type'],
        'status': status,
    }


def ping_to_json(row):
    """Serialize a ping_history row to its public JSON shape."""
    return {
        'id': row['id'],
        'status': row['status'],
        'response_time': row['response_time'],
        'checked_at': row['checked_at'],
    }


def backup_to_json(row, include_config=False):
    """Serialize a config_backups row to its public JSON shape.

    The single definition of the backup JSON shape. List rows carry a 'size'
    (the length of config_text) and use the summary shape; the single-backup
    view passes include_config=True to return the full 'config_text' instead.
    """
    data = {
        'id': row['id'],
        'created_at': row['created_at'],
    }
    if include_config:
        data['config_text'] = row['config_text']
    else:
        data['size'] = row['size']
    return data


@api.route('/devices')
def list_devices():
    """Return all devices as a JSON array.

    Online/offline status is derived from the most recent ping_history
    row per device — the same logic the dashboard uses. SSH credentials
    (ssh_username / ssh_password) are deliberately excluded.
    """
    rows = get_all_devices()
    return jsonify([device_to_json(row) for row in rows])


def _norm(value):
    """Strip strings; leave other types (incl. None) untouched."""
    return value.strip() if isinstance(value, str) else value


# Device fields that must be JSON strings (or null/absent) when supplied. The
# web-form path always yields strings, but a JSON client can send a number,
# bool, or array. Without this guard a non-string name/ip_address would reach
# .strip() in validate_device_data and raise AttributeError → HTTP 500; here it
# becomes a clean 400 client error instead. null stays allowed (treated as empty).
_STRING_FIELDS = (
    'name', 'ip_address', 'device_type',
    'ssh_username', 'ssh_password', 'enable_secret', 'netmiko_device_type',
)


def _string_type_errors(data):
    """Return a '<field> must be a string' error for each non-string, non-null field."""
    return [
        f'{field} must be a string'
        for field in _STRING_FIELDS
        if data.get(field) is not None and not isinstance(data.get(field), str)
    ]


@api.route('/devices', methods=['POST'])
def create_device_json():
    """Create a device from a JSON body. Mirrors the web Add Device form."""
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'request body must be valid JSON'}), 400
    if not isinstance(data, dict):
        return jsonify({'error': 'request body must be a JSON object'}), 400

    type_errors = _string_type_errors(data)
    if type_errors:
        return jsonify({'errors': type_errors}), 400

    device = {
        'name': _norm(data.get('name')),
        'ip_address': _norm(data.get('ip_address')),
        'device_type': _norm(data.get('device_type')) or 'Unknown',
        'ssh_username': _norm(data.get('ssh_username')) or None,
        'ssh_password': _norm(data.get('ssh_password')) or None,
        'enable_secret': _norm(data.get('enable_secret')) or None,
        'netmiko_device_type': _norm(data.get('netmiko_device_type')) or None,
    }

    errors = validate_device_data(device)
    if errors:
        return jsonify({'errors': errors}), 400

    try:
        new_id = create_device(device)
    except sqlite3.IntegrityError:
        return jsonify({'error': 'a device with this IP address already exists'}), 409

    new_row = get_device(new_id)
    response = jsonify(device_to_json(new_row))
    response.headers['Location'] = url_for('api.get_device_json', id=new_id)
    return response, 201


@api.route('/devices/<int:id>')
def get_device_json(id):
    """Return a single device as JSON, or a JSON 404 if it does not exist."""
    device = get_device(id)
    if device is None:
        return jsonify({'error': 'device not found'}), 404
    return jsonify(device_to_json(device))


@api.route('/devices/<int:id>', methods=['PUT'])
def update_device_json(id):
    """Full-replace update of a device's editable fields.

    Exception: ssh_password and enable_secret follow the password-keep rule —
    a missing key keeps the stored value (an explicit empty value clears it).
    """
    existing = get_device(id)
    if existing is None:
        return jsonify({'error': 'device not found'}), 404

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'request body must be valid JSON'}), 400
    if not isinstance(data, dict):
        return jsonify({'error': 'request body must be a JSON object'}), 400

    type_errors = _string_type_errors(data)
    if type_errors:
        return jsonify({'errors': type_errors}), 400

    # Password-keep rule: key on PRESENCE, not truthiness.
    if 'ssh_password' in data:
        ssh_password = _norm(data.get('ssh_password')) or None
    else:
        ssh_password = existing['ssh_password']

    if 'enable_secret' in data:
        enable_secret = _norm(data.get('enable_secret')) or None
    else:
        enable_secret = existing['enable_secret']

    device = {
        'name': _norm(data.get('name')),
        'ip_address': _norm(data.get('ip_address')),
        'device_type': _norm(data.get('device_type')) or 'Unknown',
        'ssh_username': _norm(data.get('ssh_username')) or None,
        'ssh_password': ssh_password,
        'enable_secret': enable_secret,
        'netmiko_device_type': _norm(data.get('netmiko_device_type')) or None,
    }

    errors = validate_device_data(device)
    if errors:
        return jsonify({'errors': errors}), 400

    try:
        update_device(id, device)
    except sqlite3.IntegrityError:
        return jsonify({'error': 'a device with this IP address already exists'}), 409

    return jsonify(device_to_json(get_device(id))), 200


@api.route('/devices/<int:id>', methods=['DELETE'])
def delete_device_json(id):
    """Delete a device, or return a JSON 404 if it does not exist."""
    device = get_device(id)
    if device is None:
        return jsonify({'error': 'device not found'}), 404
    delete_device(id)
    return '', 204


@api.route('/devices/<int:device_id>/history')
def get_device_history(device_id):
    """Return a device's ping history (newest first), or a JSON 404.

    The before_request hook already enforces Bearer auth on /api/v1/*.
    """
    if get_device(device_id) is None:
        return jsonify({'error': 'device not found'}), 404
    rows = get_ping_history(device_id)
    return jsonify([ping_to_json(row) for row in rows])


@api.route('/devices/<int:device_id>/backups')
def get_device_backups(device_id):
    """Return a device's config backups (summary, newest first), or a JSON 404.

    Each entry carries the config size, not the full config_text — fetch a
    single backup to read its contents.
    """
    if get_device(device_id) is None:
        return jsonify({'error': 'device not found'}), 404
    rows = get_backups(device_id)
    return jsonify([backup_to_json(row) for row in rows])


@api.route('/devices/<int:device_id>/backups/<int:backup_id>')
def get_device_backup(device_id, backup_id):
    """Return a single config backup (including config_text), or a JSON 404.

    404 if the device does not exist, or if no backup with that id belongs to
    it — the lookup is scoped to the device id, so another device's backup
    cannot be read by guessing the id.
    """
    if get_device(device_id) is None:
        return jsonify({'error': 'device not found'}), 404
    backup = get_backup(device_id, backup_id)
    if backup is None:
        return jsonify({'error': 'backup not found'}), 404
    return jsonify(backup_to_json(backup, include_config=True))


@api.route('/devices/<int:device_id>/drift')
def get_device_drift(device_id):
    """Return the config drift between two of a device's backups, or a JSON error.

    Optional ?from=<older id>&to=<newer id> select the pair; both default to the
    two most recent backups when missing or invalid. Mirrors the web
    /device/<id>/drift view. get_backup is scoped to the device id, so a
    missing/foreign id returns None and falls back to a default — that scoping
    is the security check. Only the structured diff is returned, never the full
    config_text.
    """
    if get_device(device_id) is None:
        return jsonify({'error': 'device not found'}), 404

    backups = get_backups(device_id)
    if len(backups) < 2:
        return jsonify({'error': 'at least two backups are required to compute drift'}), 400

    from_id = request.args.get('from', type=int)
    to_id = request.args.get('to', type=int)

    # Default: from = second newest (older), to = newest (newer), so the diff
    # reads older -> newer.
    old_row = get_backup(device_id, from_id)
    if old_row is None:
        old_row = get_backup(device_id, backups[1]['id'])
    new_row = get_backup(device_id, to_id)
    if new_row is None:
        new_row = get_backup(device_id, backups[0]['id'])

    result = compute_drift(old_row['config_text'], new_row['config_text'])
    return jsonify({
        'device_id': device_id,
        'from': {'id': old_row['id'], 'created_at': old_row['created_at']},
        'to': {'id': new_row['id'], 'created_at': new_row['created_at']},
        'identical': result['identical'],
        'added': result['added'],
        'removed': result['removed'],
        'diff': result['lines'],
    })
