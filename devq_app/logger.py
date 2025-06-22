# logger.py
from threading import Thread
import datetime

def log_event(message):
    def write_log():
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open("logs.txt", "a") as log_file:
            log_file.write(f"[{timestamp}] {message}\n")
    Thread(target=write_log).start()
