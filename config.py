import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DATABASE = os.path.join(BASE_DIR, 'netmonitor.db')
PING_INTERVAL = 60  # seconds between monitoring cycles
SECRET_KEY = 'dev-secret-key-change-in-production'
