from devq_app import create_app, socketio

app = create_app()

if __name__ == "__main__":
    socketio.run(app, debug=True)
with app.app_context():
    print("Registered routes:")
    for rule in app.url_map.iter_rules():
        print(rule)

# This is the entry point for the Flask application.
# It creates the Flask app using the factory function and runs the SocketIO server.