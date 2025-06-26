# main.py
from devq_app import create_app, socketio
import os
import sys # Add this line
import pkg_resources # Add this line

print("⚙️ Starting Flask App")
print("Using DB URL:", os.environ.get("DATABASE_URL"))
print(f"Python executable: {sys.executable}") # This will show the Python executable path

# Attempt to get versions at runtime
try:
    flask_socketio_version = pkg_resources.get_distribution("Flask-SocketIO").version
    python_socketio_version = pkg_resources.get_distribution("python-socketio").version
    print(f"Flask-SocketIO version (runtime): {flask_socketio_version}")
    print(f"python-socketio version (runtime): {python_socketio_version}")
except pkg_resources.DistributionNotFound:
    print("Flask-SocketIO or python-socketio not found at runtime in this environment.")
except Exception as e:
    print(f"Error getting package versions at runtime: {e}")

app = create_app()

# This prints all routes (for debugging)
with app.app_context():
    print("Registered routes:")
    for rule in app.url_map.iter_rules():
        print(rule)

if __name__ == '__main__':
    # Assuming you run your app using socketio.run
    socketio.run(app, debug=True)