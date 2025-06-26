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
# Add this block to run the development server
if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    # Alternatively, for basic Flask without SocketIO integration needed for running:
    # app.run(debug=True, host='0.0.0.0', port=5000)