from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.secret_key = "your_secret_key"

    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:NBsql2003*@localhost:5432/devqdb'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_TYPE'] = 'filesystem'

    db.init_app(app)
    Session(app)

    with app.app_context():
        from devq_app import routes
        db.create_all()
    return app
# This function initializes the Flask application, sets up the database connection,
# and registers the routes. It uses SQLAlchemy for ORM and Flask-Session for session management