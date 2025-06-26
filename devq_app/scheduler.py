# devq_app/scheduler.py

from .models import User, Query
from . import db
from .logger import log_event

def assign_mentor():
    """
    Automates the assignment of 'Open' queries to mentors based on
    matching query tags with mentor expertise and mentor load balancing.
    This is for bulk, periodic assignments.
    """
    log_event("Scheduler: Attempting automated query assignment (bulk run)...")

    mentors = User.query.filter_by(role='mentor').all()
    if not mentors:
        log_event("Scheduler: No mentors available for assignment (bulk).")
        return []

    open_queries = Query.query.filter_by(status='Open', assigned_to=None).all()
    if not open_queries:
        log_event("Scheduler: No new 'Open' queries to process (bulk).")
        return []

    assigned_query_ids = []

    mentor_load = {mentor.userid: 0 for mentor in mentors}
    current_assignments = Query.query.filter(
        Query.assigned_to.isnot(None),
        Query.status.in_(['In Progress', 'Pending'])
    ).all()

    for q in current_assignments:
        if q.assigned_to in mentor_load:
            mentor_load[q.assigned_to] += 1

    mentor_expertise_sets = {
        mentor.userid: set(tag.strip() for tag in mentor.expertise.split(',')) if mentor.expertise else set()
        for mentor in mentors
    }

    for query in open_queries:
        query_tags_set = set(tag.strip() for tag in query.tags.split(',')) if query.tags else set()

        eligible_mentors_for_query = {}
        for mentor_id, expertise_set in mentor_expertise_sets.items():
            if query_tags_set.issubset(expertise_set) or not query_tags_set:
                eligible_mentors_for_query[mentor_id] = mentor_load.get(mentor_id, 0)

        if not eligible_mentors_for_query:
            log_event(f"Scheduler: No eligible mentor found for Query ID {query.id} (Tags: {query.tags}). Skipping (bulk).")
            continue

        best_mentor_id = min(eligible_mentors_for_query, key=eligible_mentors_for_query.get)
        
        query.assigned_to = best_mentor_id
        query.status = 'In Progress'
        db.session.add(query)

        assigned_query_ids.append(query.id)
        mentor_load[best_mentor_id] += 1
        
        log_event(f"Scheduler: Assigned Query ID {query.id} (Tags: {query.tags}) to Mentor {best_mentor_id} (bulk).")

    if assigned_query_ids:
        db.session.commit()
        log_event(f"Scheduler: Successfully committed assignments for queries: {assigned_query_ids} (bulk).")
    else:
        db.session.rollback()
        log_event("Scheduler: No queries were assigned in this run after processing (bulk).")

    return assigned_query_ids

# NEW HELPER FUNCTION FOR TARGETED RE-ASSIGNMENT (MENTOR REVOKE)
def find_and_assign_single_query(query_id, exclude_mentor_id=None):
    """
    Attempts to assign a single query to an eligible mentor,
    optionally excluding a specific mentor (e.g., the one who just revoked).
    Returns the userid of the assigned mentor, or None if no one else could be assigned.
    """
    query = Query.query.get(query_id)
    if not query or query.status != 'Open' or query.assigned_to is not None:
        log_event(f"Scheduler Helper: Query {query_id} not eligible for single re-assignment (status: {query.status}, assigned_to: {query.assigned_to}).")
        return None

    log_event(f"Scheduler Helper: Attempting to find new mentor for Query ID {query_id}, excluding {exclude_mentor_id}.")

    mentors = User.query.filter_by(role='mentor').all()
    if not mentors:
        log_event("Scheduler Helper: No mentors available for assignment.")
        return None

    mentor_load = {mentor.userid: 0 for mentor in mentors}
    current_assignments = Query.query.filter(
        Query.assigned_to.isnot(None),
        Query.status.in_(['In Progress', 'Pending'])
    ).all()

    for q_assigned in current_assignments:
        if q_assigned.assigned_to in mentor_load:
            mentor_load[q_assigned.assigned_to] += 1

    mentor_expertise_sets = {
        mentor.userid: set(tag.strip() for tag in mentor.expertise.split(',')) if mentor.expertise else set()
        for mentor in mentors
    }

    query_tags_set = set(tag.strip() for tag in query.tags.split(',')) if query.tags else set()

    eligible_mentors_for_query = {}
    for mentor_id, expertise_set in mentor_expertise_sets.items():
        if mentor_id == exclude_mentor_id: # EXCLUDE the specified mentor
            continue
        if query_tags_set.issubset(expertise_set) or not query_tags_set:
            eligible_mentors_for_query[mentor_id] = mentor_load.get(mentor_id, 0)

    if not eligible_mentors_for_query:
        log_event(f"Scheduler Helper: No *other* eligible mentor found for Query ID {query_id} (Tags: {query.tags}).")
        return None # No other mentor found

    best_mentor_id = min(eligible_mentors_for_query, key=eligible_mentors_for_query.get)
    
    # Assign the query immediately within this function and commit
    query.assigned_to = best_mentor_id
    query.status = 'In Progress'
    db.session.add(query)
    db.session.commit()
    
    log_event(f"Scheduler Helper: Successfully reassigned Query ID {query.id} to new Mentor {best_mentor_id}.")
    return best_mentor_id # Return the ID of the new mentor who was assigned