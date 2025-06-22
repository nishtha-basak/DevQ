from .models import User, Query
from . import db

def assign_mentor():
    mentors = User.query.filter_by(role='mentor').all()
    if not mentors:
        return None

    # Load balancing: find mentor with fewest open queries
    mentor_load = {mentor.id: 0 for mentor in mentors}
    open_queries = Query.query.filter_by(status="pending").all()

    for query in open_queries:
        if query.assigned_to:
            mentor_load[query.assigned_to] += 1

    best_mentor = min(mentor_load, key=mentor_load.get)
    return best_mentor
