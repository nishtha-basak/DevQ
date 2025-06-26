from flask import Blueprint, render_template, request, redirect, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import aliased
from devq_app import db, socketio # socketio is imported globally
from devq_app.models import User, Query
from devq_app.logger import log_event

routes = Blueprint('routes', __name__)

ROLE_SUFFIX = {
    'developer': 'D',
    'mentor': 'M',
    'admin': 'A'
}

@routes.route('/healthz')
def health_check():
    return "OK", 200

@routes.route('/')
def welcome():
    return render_template('welcome.html')

@routes.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        next_id = (User.query.count() or 0) + 101
        role_suffix = ROLE_SUFFIX.get(role.lower(), 'X')
        userid = f"{next_id}{role_suffix}"

        if User.query.filter_by(userid=userid).first():
            flash("User ID exists. Try again.", "danger")
            return redirect('/signup')

        hashed_password = generate_password_hash(password)
        user = User(username=username, userid=userid, password=hashed_password, role=role)

        db.session.add(user)
        db.session.commit()

        log_event(f"Sign-Up: {user.username} (ID: {user.userid}, Role: {user.role})")
        flash(f"Registered! Your ID is {userid}", "success")
        return redirect('/login')

    return render_template('signup.html')

@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        userid = request.form['userid'].strip()
        password = request.form['password']
        role = request.form['role']

        user = User.query.filter_by(userid=userid).first()

        if not user:
            flash("User not found. Please sign up.", "danger")
            return redirect('/signup')

        if user.role != role:
            flash(f"You are registered as {user.role.title()}.", "warning")
            return redirect('/login')

        if not check_password_hash(user.password, password):
            flash("Wrong password.", "danger")
            return redirect('/login')

        session.clear()
        session['userid'] = user.userid
        session['username'] = user.username
        session['role'] = user.role

        log_event(f"Login: {user.username} (ID: {user.userid}, Role: {user.role})")
        flash(f"Welcome {user.username}!", "success")

        return redirect(f"/{role.lower()}")

    return render_template('login.html')

@routes.route('/logout')
def logout():
    user = session.get('username', 'Unknown')
    role = session.get('role', 'Unknown')
    userid = session.get('userid', 'Unknown')
    log_event(f"Logout: {user} ({role}, ID: {userid})")
    session.clear()
    flash("Logged out.", "info")
    return redirect('/')

# ---------------- Developer ----------------

@routes.route('/developer', methods=['GET', 'POST'])
def developer():
    if session.get('role') != 'developer':
        flash("Access denied.", "danger")
        return redirect('/login')

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        submitted_by = session['userid']
        new_query = Query(title=title, description=description, submitted_by=submitted_by)
        db.session.add(new_query)
        db.session.commit()

        log_event(f"Query Submitted by {session['username']} ({session['userid']}): {title} - {description}")
        
        # --- MODIFIED: Emitting a 'query_updated' event for new query ---
        socketio.emit('query_updated', {
            'query_id': new_query.id,
            'action': 'new',
            'title': title,
            'description': description,
            'submitted_by': submitted_by,
            'developer_name': session['username'], # Pass developer's username
            'status': new_query.status # Pass initial status
        }, namespace='/')
        # --- END MODIFIED ---

        flash("Query submitted!", "success")
        return redirect('/developer')

    Mentor = aliased(User)
    queries = db.session.query(Query, Mentor.username.label('mentor_name')) \
        .outerjoin(Mentor, Query.assigned_to == Mentor.userid) \
        .filter(Query.submitted_by == session['userid']).all()

    enriched_queries = []
    for q, mentor_name in queries:
        q.mentor_name = mentor_name
        enriched_queries.append(q)

    return render_template('developer.html', queries=enriched_queries)

@routes.route('/developer/edit/<int:qid>', methods=['GET', 'POST'])
def edit_query(qid):
    query = Query.query.get_or_404(qid)
    if session.get('userid') != query.submitted_by:
        flash("Unauthorized.", "danger")
        return redirect('/developer')
    
    # Developers can only edit 'Open' or 'Pending' queries
    if query.status not in ['Open', 'Pending']:
        flash("Cannot edit a query that is in progress or resolved.", "danger")
        return redirect('/developer')

    if request.method == 'POST':
        query.title = request.form['title']
        query.description = request.form['description']
        db.session.commit()
        log_event(f"Query Edited by {session['username']} ({session['userid']}): {query.title}")

        # --- MODIFIED: Emitting a 'query_updated' event for edited query ---
        socketio.emit('query_updated', {
            'query_id': query.id,
            'action': 'edited',
            'title': query.title,
            'description': query.description,
            'submitted_by': query.submitted_by,
            'edited_by': session['username']
        }, namespace='/')
        # --- END MODIFIED ---

        flash("Query updated.", "success")
        return redirect('/developer')
    return render_template('edit_query.html', query=query)

@routes.route('/developer/delete/<int:qid>', methods=['POST'])
def delete_query(qid):
    q = Query.query.get_or_404(qid)
    if session['userid'] == q.submitted_by and q.status != 'Resolved':
        log_event(f"Query Deleted by {session['username']} ({session['userid']}): {q.title}")
        db.session.delete(q)
        db.session.commit()
        
        # --- MODIFIED: Emitting a 'query_updated' event for deleted query ---
        socketio.emit('query_updated', {
            'query_id': q.id,
            'action': 'deleted',
            'title': q.title,
            'submitted_by': q.submitted_by,
            'deleted_by': session['username']
        }, namespace='/')
        # --- END MODIFIED ---

        flash("Query deleted.", "success")
    else:
        flash("Not allowed.", "danger")
    return redirect('/developer')

# ---------------- Mentor ----------------

@routes.route('/mentor')
def mentor():
    if session.get('role') != 'mentor':
        flash("Mentor access only.", "danger")
        return redirect('/login')

    # Fetch queries submitted by any developer, and those assigned to current mentor
    # Also include the developer's username for display
    Developer = aliased(User)
    queries = db.session.query(Query, Developer.username.label('developer_name')) \
        .join(Developer, Query.submitted_by == Developer.userid) \
        .filter(
            (Query.assigned_to == None) | (Query.assigned_to == session['userid'])
        ).all()
    
    enriched_queries = []
    for q, dev_name in queries:
        q.developer_name = dev_name
        enriched_queries.append(q)

    return render_template('mentor.html', queries=enriched_queries)

@routes.route('/mentor/accept/<int:query_id>', methods=['POST'])
def accept_query(query_id):
    query = Query.query.get_or_404(query_id)
    if query.assigned_to is None:
        query.assigned_to = session['userid']
        query.status = 'In Progress'
        db.session.commit()
        log_event(f"Query Accepted by Mentor {session['username']} ({session['userid']}): {query.title}")
        
        # --- MODIFIED: Emitting a 'query_updated' event for accepted query ---
        socketio.emit('query_updated', {
            'query_id': query.id,
            'action': 'accepted',
            'title': query.title,
            'assigned_to': session['userid'],
            'mentor_name': session['username'],
            'status': 'In Progress'
        }, namespace='/')
        # --- END MODIFIED ---

        flash("Accepted.", "success")
    else:
        flash("Already assigned.", "warning")
    return redirect('/mentor')

@routes.route('/mentor/revoke/<int:qid>', methods=['POST'])
def revoke_query(qid):
    q = Query.query.get_or_404(qid)
    if q.assigned_to == session['userid']:
        q.assigned_to = None
        q.status = 'Pending'
        db.session.commit()
        log_event(f"Mentor {session['username']} ({session['userid']}) revoked query: {q.title}")
        
        # --- MODIFIED: Emitting a 'query_updated' event for revoked query ---
        socketio.emit('query_updated', {
            'query_id': q.id,
            'action': 'revoked',
            'title': q.title,
            'revoked_by': session['username'],
            'status': 'Pending'
        }, namespace='/')
        # --- END MODIFIED ---

        flash("Revoked.", "info")
    else:
        flash("Unauthorized.", "danger")
    return redirect('/mentor')

@routes.route('/mentor/update_status/<int:query_id>', methods=['POST'])
def update_status(query_id):
    query = Query.query.get_or_404(query_id)
    # Mentors can only update status of queries assigned to them, or "Open" queries if they're about to accept
    if query.assigned_to != session['userid'] and query.status != 'Open':
        flash("Unauthorized. You can only update status for queries assigned to you.", "danger")
        return redirect('/mentor')

    new_status = request.form.get('status')
    old_status = query.status
    query.status = new_status
    db.session.commit()
    log_event(f"Mentor {session['username']} ({session['userid']}) updated status from {old_status} to {new_status} for: {query.title}")
    
    # --- MODIFIED: Emitting a 'query_updated' event for status change ---
    socketio.emit('query_updated', {
        'query_id': query.id,
        'action': 'status_change',
        'title': query.title,
        'old_status': old_status,
        'new_status': new_status,
        'updated_by_mentor': session['username']
    }, namespace='/')
    # --- END MODIFIED ---

    flash("Status updated.", "success")
    return redirect('/mentor')

@routes.route('/mentor/solve/<int:qid>', methods=['POST'])
def solve_query(qid):
    q = Query.query.get_or_404(qid)
    if q.assigned_to != session['userid']:
        flash("Unauthorized.", "danger")
        return redirect('/mentor')
    q.solution = request.form['solution']
    q.status = 'Resolved'
    db.session.commit()
    log_event(f"Mentor {session['username']} ({session['userid']}) resolved query {q.title} with solution update.")
    
    # --- MODIFIED: Emitting a 'query_updated' event for solution submission ---
    socketio.emit('query_updated', {
        'query_id': q.id,
        'action': 'resolved',
        'title': q.title,
        'mentor_id': session['userid'],
        'mentor_name': session['username'],
        'status': 'Resolved',
        'solution_text': q.solution
    }, namespace='/')
    # --- END MODIFIED ---

    flash("Solution submitted.", "success")
    return redirect('/mentor')

# ---------------- Admin ----------------

@routes.route('/admin')
def admin():
    if session.get('role') != 'admin':
        return redirect('/login')

    Developer = aliased(User)
    Mentor = aliased(User)

    raw_data = db.session.query(Query, Developer.username.label('developer_name'), Mentor.username.label('mentor_name')) \
        .outerjoin(Developer, Query.submitted_by == Developer.userid) \
        .outerjoin(Mentor, Query.assigned_to == Mentor.userid) \
        .all()

    queries = []
    for q, dev_name, ment_name in raw_data:
        q.developer_name = dev_name
        q.mentor_name = ment_name
        queries.append(q)

    all_mentors = User.query.filter_by(role='mentor').all()
    # Find currently assigned mentor IDs from queries
    assigned_mentor_userids = [q.assigned_to for q in Query.query.filter(Query.assigned_to.isnot(None)).all()]
    # Filter out mentors who are already assigned to a query from the "free_mentors" list
    # This logic may need refinement depending on if a mentor can be assigned to multiple queries
    # For now, assuming a mentor can only be assigned to one query at a time for "free" status
    free_mentors = [m for m in all_mentors if m.userid not in assigned_mentor_userids]

    return render_template('admin.html', queries=queries, mentors=free_mentors)


@routes.route('/admin/assign/<int:query_id>', methods=['POST'])
def admin_assign_mentor(query_id): # Renamed to avoid conflict with scheduler's assign_mentor
    mentor_id = request.form['mentor_id']
    query = Query.query.get_or_404(query_id)
    
    # Fetch mentor's username for the event payload
    assigned_mentor_user = User.query.filter_by(userid=mentor_id).first()
    mentor_username = assigned_mentor_user.username if assigned_mentor_user else None

    if query.assigned_to:
        flash("Already assigned.", "warning")
    else:
        query.assigned_to = mentor_id
        query.status = 'In Progress'
        db.session.commit()
        log_event(f"Admin {session['username']} assigned mentor {mentor_id} to query {query.title}")
        
        # --- MODIFIED: Emitting a 'query_updated' event for admin assignment ---
        socketio.emit('query_updated', {
            'query_id': query.id,
            'action': 'assigned_by_admin',
            'title': query.title,
            'assigned_to': mentor_id,
            'mentor_name': mentor_username, # Pass mentor's username
            'admin_name': session['username'],
            'status': 'In Progress'
        }, namespace='/')
        # --- END MODIFIED ---

        flash("Mentor assigned.", "success")
    return redirect('/admin')

@routes.route('/admin/revoke/<int:query_id>', methods=['POST'])
def admin_revoke_mentor(query_id): # Renamed to avoid conflict
    query = Query.query.get_or_404(query_id)
    if not query.assigned_to:
        flash("No mentor assigned.", "info")
    else:
        log_event(f"Admin {session['username']} revoked mentor {query.assigned_to} from {query.title}")
        
        # Store revoked mentor's ID before nullifying
        revoked_mentor_id = query.assigned_to 
        revoked_mentor_user = User.query.filter_by(userid=revoked_mentor_id).first()
        revoked_mentor_name = revoked_mentor_user.username if revoked_mentor_user else None

        query.assigned_to = None
        query.status = 'Pending'
        db.session.commit()
        
        # --- MODIFIED: Emitting a 'query_updated' event for admin revocation ---
        socketio.emit('query_updated', {
            'query_id': query.id,
            'action': 'revoked_by_admin',
            'title': query.title,
            'revoked_mentor_id': revoked_mentor_id,
            'revoked_mentor_name': revoked_mentor_name,
            'admin_name': session['username'],
            'status': 'Pending'
        }, namespace='/')
        # --- END MODIFIED ---

        flash("Revoked.", "success")
    return redirect('/admin')

# ---------------- Profile Management ----------------

@routes.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    userid = session.get('userid')
    print("USERID:", userid)
    print("POST DATA:", request.form)

    if not userid:
        flash("Please log in first.", "danger")
        return redirect('/login')

    user = User.query.filter_by(userid=userid).first()
    if not user:
        flash("User not found.", "danger")
        return redirect('/login')

    try:
        if request.method == 'POST':
            new_username = request.form.get('username')
            new_password = request.form.get('password')

            user.username = new_username
            if new_password and new_password.strip():
                user.password = generate_password_hash(new_password)

            db.session.commit()
            log_event(f"Profile Updated: {user.username} (ID: {user.userid}, Role: {user.role})")
            # Update session username if it changed
            if session['username'] != new_username:
                session['username'] = new_username
            
            flash("Profile updated successfully.", "success")
            return redirect(f"/{user.role.lower()}")
    except Exception as e:
        print("Error in update_profile:", e)
        import traceback
        print(traceback.format_exc())
        flash("An error occurred. Please try again later.", "danger")
    print("Rendering template with user:", user)

    try:
        return render_template('update_profile.html', user=user)
    except Exception as e:
        print("Template rendering error:", e)
        import traceback
        print(traceback.format_exc())
        flash("Template error. Check server logs.", "danger")
        return redirect(f"/{user.role.lower()}")

@routes.route('/delete_account', methods=['POST'])
def delete_account():
    if 'userid' not in session:
        return redirect('/login')

    user = User.query.filter_by(userid=session['userid']).first()

    # Also delete user's queries
    Query.query.filter((Query.submitted_by == user.userid) | (Query.assigned_to == user.userid)).delete()
    db.session.delete(user)
    db.session.commit()

    log_event(f"Account Deleted: {user.username} (ID: {user.userid}, Role: {user.role})")
    session.clear()
    flash("Your account has been deleted.", "info")
    return redirect('/')