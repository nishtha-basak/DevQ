# devq_app/scheduler.py

from .models import User, Query
from . import db # Assuming db is initialized and available
from .logger import log_event # Make sure logger is imported correctly

def assign_mentor():
    """
    Automates the assignment of 'Open' queries to mentors based on
    matching query tags with mentor expertise and mentor load balancing.
    """
    log_event("Scheduler: Attempting automated query assignment...")

    # Fetch all active mentors
    mentors = User.query.filter_by(role='mentor').all()
    if not mentors:
        log_event("Scheduler: No mentors available for assignment.")
        return []

    # Get all currently 'Open' queries that are not yet assigned
    open_queries = Query.query.filter_by(status='Open', assigned_to=None).all()
    if not open_queries:
        log_event("Scheduler: No new 'Open' queries to process for automatic assignment.")
        return []

    assigned_query_ids = []

    # 1. Calculate current load for all mentors (only 'In Progress' or 'Pending' queries)
    mentor_load = {mentor.userid: 0 for mentor in mentors}
    current_assignments = Query.query.filter(
        Query.assigned_to.isnot(None),
        Query.status.in_(['In Progress', 'Pending'])
    ).all()

    for q in current_assignments:
        if q.assigned_to in mentor_load:
            mentor_load[q.assigned_to] += 1

    # 2. Prepare mentor expertise for efficient lookup (convert to sets)
    mentor_expertise_sets = {
        mentor.userid: set(tag.strip() for tag in mentor.expertise.split(',')) if mentor.expertise else set()
        for mentor in mentors
    }

    # 3. Process each open query for assignment
    for query in open_queries:
        query_tags_set = set(tag.strip() for tag in query.tags.split(',')) if query.tags else set()

        # Find eligible mentors for this specific query
        eligible_mentors_for_query = {}
        for mentor_id, expertise_set in mentor_expertise_sets.items():
            if query_tags_set.issubset(expertise_set) or not query_tags_set:
                eligible_mentors_for_query[mentor_id] = mentor_load.get(mentor_id, 0)

        if not eligible_mentors_for_query:
            log_event(f"Scheduler: No eligible mentor found for Query ID {query.id} (Tags: {query.tags}). Skipping.")
            continue

        # 4. Select the best mentor (least loaded among eligible)
        best_mentor_id = min(eligible_mentors_for_query, key=eligible_mentors_for_query.get)
        
        # 5. Assign the query
        query.assigned_to = best_mentor_id
        query.status = 'In Progress'
        db.session.add(query)

        assigned_query_ids.append(query.id)
        mentor_load[best_mentor_id] += 1
        
        log_event(f"Scheduler: Assigned Query ID {query.id} (Tags: {query.tags}) to Mentor {best_mentor_id}.")

    # 6. Commit all changes made in this run
    if assigned_query_ids:
        db.session.commit()
        log_event(f"Scheduler: Successfully committed assignments for queries: {assigned_query_ids}")
    else:
        db.session.rollback()
        log_event("Scheduler: No queries were assigned in this run after processing.")

    return assigned_query_ids