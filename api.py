import hmac
import os
import sqlite3

from flask import Blueprint, jsonify, request, url_for

from models import create_device, delete_device, get_all_devices, get_device, update_device, validate_device_data

# Read-only JSON API. Mounted under /api/v1 (see app.py).
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


@api.route('/devices', methods=['POST'])
def create_device_json():
    """Create a device from a JSON body. Mirrors the web Add Device form."""
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'request body must be valid JSON'}), 400

    device = {
        'name': _norm(data.get('name')),
        'ip_address': _norm(data.get('ip_address')),
        'device_type': _norm(data.get('device_type')) or 'Unknown',
        'ssh_username': _norm(data.get('ssh_username')) or None,
        'ssh_password': _norm(data.get('ssh_password')) or None,
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

    Exception: ssh_password follows the password-keep rule — a missing
    'ssh_password' key keeps the stored value (an explicit empty value clears it).
    """
    existing = get_device(id)
    if existing is None:
        return jsonify({'error': 'device not found'}), 404

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'request body must be valid JSON'}), 400

    # Password-keep rule: key on PRESENCE, not truthiness.
    if 'ssh_password' in data:
        ssh_password = _norm(data.get('ssh_password')) or None
    else:
        ssh_password = existing['ssh_password']

    device = {
        'name': _norm(data.get('name')),
        'ip_address': _norm(data.get('ip_address')),
        'device_type': _norm(data.get('device_type')) or 'Unknown',
        'ssh_username': _norm(data.get('ssh_username')) or None,
        'ssh_password': ssh_password,
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
