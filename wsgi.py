from app import app
from models import init_db, seed_devices
from monitor import start_monitor

init_db()
seed_devices()
start_monitor()

if __name__ == '__main__':
    app.run()
