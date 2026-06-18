import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DATABASE = os.path.join(BASE_DIR, 'netmonitor.db')
PING_INTERVAL = 60  # seconds between monitoring cycles

# Flask signs session cookies and flash messages with this key. Production
# supplies it via the NETMONITOR_SECRET_KEY environment variable, mirroring how
# the API key is read from the environment (see api.py). The literal below is a
# DEV-ONLY fallback — it is not a real secret (the repo is public), so never
# rely on it in production.
SECRET_KEY = os.environ.get('NETMONITOR_SECRET_KEY', 'dev-secret-key-change-in-production')
