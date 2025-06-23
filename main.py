from devq_app import create_app, socketio
import os

print("⚙️ Starting Flask App")
print("Using DB URL:", os.environ.get("DATABASE_URL"))

app = create_app()

# This prints all routes (for debugging)
with app.app_context():
    print("Registered routes:")
    for rule in app.url_map.iter_rules():
        print(rule)
