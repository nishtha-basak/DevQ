# logger.py
from threading import Thread, Lock
from datetime import datetime
import os

log_lock = Lock()  # Thread-safe logging

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs.txt')

def log_event(message):
    def write_log():
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"

        with log_lock:  # Ensure thread-safe file writing
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(log_entry)

    Thread(target=write_log).start()
