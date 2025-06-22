from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_socketio import SocketIO

# Initialize extensions globally
socketio = SocketIO(cors_allowed_origins="*")  # Allow frontend access from any origin
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.secret_key = "your_secret_key"

    # Database Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:NBsql2003*@localhost:5432/devqdb'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Session Configuration
    app.config['SESSION_TYPE'] = 'filesystem'

    # Initialize extensions with the app
    db.init_app(app)
    Session(app)

    # ✅ Register the blueprint
    from devq_app.routes import routes as routes_blueprint
    app.register_blueprint(routes_blueprint)

    with app.app_context():
        db.create_all()

    socketio.init_app(app)
    return app
