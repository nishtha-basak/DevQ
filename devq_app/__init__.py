# devq_app/__init__.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_socketio import SocketIO
from apscheduler.schedulers.background import BackgroundScheduler
import os
from dotenv import load_dotenv

# Initialize extensions globally
socketio = SocketIO(cors_allowed_origins="*")
db = SQLAlchemy()
load_dotenv()

# REMOVED: Global 'scheduler' instance from here

def create_app():
    app = Flask(__name__)
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

    app.config['SESSION_TYPE'] = 'filesystem'

    db.init_app(app)
    Session(app)

    # NEW: Make 'set' available in Jinja2 templates
    app.jinja_env.globals.update(set=set) # This line adds the 'set' function

    from devq_app.routes import routes as routes_blueprint
    app.register_blueprint(routes_blueprint)

    with app.app_context():
        db.create_all()

    socketio.init_app(app)

    if not hasattr(app, 'scheduler'):
        app.scheduler = BackgroundScheduler()
        from devq_app.scheduler import assign_mentor
        from devq_app.models import Query, User
        from devq_app.logger import log_event

        def scheduled_assignment_job():
            with app.app_context():
                log_event("APScheduler: Running automated query assignment job...")
                assigned_ids = assign_mentor()
                if assigned_ids:
                    for query_id in assigned_ids:
                        query = Query.query.get(query_id)
                        if query:
                            mentor_name = User.query.filter_by(userid=query.assigned_to).first().username if query.assigned_to else 'Unassigned'
                            developer_name = User.query.filter_by(userid=query.submitted_by).first().username if query.submitted_by else 'Unknown Developer'
                            
                            log_event(f"APScheduler: Emitting update for automatically assigned Query ID {query.id} to {mentor_name}.")
                            
                            socketio.emit('query_updated', {
                                'query_id': query.id,
                                'action': 'auto_assigned',
                                'title': query.title,
                                'description': query.description,
                                'tags': query.tags,
                                'status': query.status,
                                'submitted_by_id': query.submitted_by,
                                'developer_name': developer_name,
                                'assigned_to_id': query.assigned_to,
                                'mentor_name': mentor_name,
                                'solution_text': query.solution
                            }, namespace='/')
                else:
                    log_event("APScheduler: No queries were assigned in this run.")

        app.scheduler.add_job(func=scheduled_assignment_job, trigger="interval", seconds=10) # Changed to minutes=2
        app.scheduler.start()
        log_event("APScheduler started and scheduled automated query assignment job.")

    return app