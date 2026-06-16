import sqlite3

from flask import Blueprint, jsonify, request, url_for

from models import create_device, get_all_devices, get_device, validate_device_data

# Read-only JSON API. Mounted under /api/v1 (see app.py).
api = Blueprint('api', __name__, url_prefix='/api/v1')


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
