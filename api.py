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
