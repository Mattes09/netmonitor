from flask import Blueprint, jsonify

from models import get_all_devices, get_device

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


@api.route('/devices/<int:id>')
def get_device_json(id):
    """Return a single device as JSON, or a JSON 404 if it does not exist."""
    device = get_device(id)
    if device is None:
        return jsonify({'error': 'device not found'}), 404
    return jsonify(device_to_json(device))
