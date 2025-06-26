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
        role = request.form['role'].lower() # Convert to lowercase for consistent suffix lookup

        # 1. Create User object without userid initially (it will be NULL)
        # The 'id' (primary key) will be auto-assigned by the database upon commit
        hashed_password = generate_password_hash(password)
        # new_user expertise will be default='', which is fine
        new_user = User(username=username, password=hashed_password, role=role)

        try:
            db.session.add(new_user)
            db.session.commit() # First commit: inserts user, DB assigns 'id', userid is NULL

            # 2. Now generate the custom userid using the database-assigned unique 'id'
            role_suffix = ROLE_SUFFIX.get(role, 'X')
            new_user.userid = f"{new_user.id}{role_suffix}" # Generate based on unique DB-assigned ID

            # 3. Update the userid and commit again
            # db.session.add(new_user) # Already tracked by session, no need to add again
            db.session.commit() # Second commit: updates userid from NULL to the generated value

            flash(f"Account created successfully! Your User ID is: {new_user.userid}", "success")
            log_event(f"New user signed up: {new_user.username} (ID: {new_user.userid}) as {new_user.role}")
            return redirect('/login')

        except Exception as e:
            db.session.rollback() # Rollback the transaction in case of any database error
            # This 'except' block will now mainly catch other unexpected DB errors
            flash(f"An unexpected error occurred during signup. Please try again. Error: {e}", "danger")
            import traceback
            log_event(f"Signup error for username {username}: {traceback.format_exc()}")
            return redirect('/signup')

    return render_template('signup.html')

@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        userid = request.form['userid'].strip()
        password = request.form['password']
        role = request.form['role'].lower() # Ensure role is lowercase for consistency

        user = User.query.filter_by(userid=userid).first()

        if not user:
            flash("User not found. Please sign up.", "danger")
            return redirect('/signup')

        if user.role != role:
            flash(f"You are registered as {user.role.title()}. Please select the correct role.", "warning")
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

        # NEW LOGIC: If mentor and expertise is not set, redirect to setup page
        # user.expertise is a string; empty string evaluates to False
        if user.role == 'mentor' and not user.expertise:
            flash("Please set your expertise to continue.", "info")
            return redirect('/mentor_setup_expertise')

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

    developer_id = session['userid']
    developer = User.query.filter_by(userid=developer_id).first() # Fetch developer object to get username for socketio emit

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        # NEW: Get selected tags from the form (multi-select)
        selected_tags = request.form.getlist('tags') # getlist for multiple selected options
        tags_string = ','.join(selected_tags) # Join into a comma-separated string

        new_query = Query(
            title=title,
            description=description,
            tags=tags_string, # Save the tags string
            submitted_by=developer_id,
            status='Open' # Initial status for new queries from developers
        )
        db.session.add(new_query)
        db.session.commit()
        flash("Query submitted successfully!", "success")
        log_event(f"Query submitted by {developer.username} ({developer.userid}): '{title}' with tags: {tags_string}")

        # Emit SocketIO event for real-time update
        # Include all relevant data for dashboards to update
        socketio.emit('query_updated', {
            'query_id': new_query.id,
            'action': 'new_query', # More specific action for frontend
            'title': new_query.title,
            'description': new_query.description,
            'tags': new_query.tags,
            'status': new_query.status,
            'submitted_by_id': new_query.submitted_by,
            'developer_name': developer.username # Pass developer's username
        }, namespace='/')

        return redirect('/developer')

    # For GET request, fetch queries
    queries = db.session.query(Query, User.username.label('mentor_name')) \
        .outerjoin(User, Query.assigned_to == User.userid) \
        .filter(Query.submitted_by == developer_id).order_by(Query.id.desc()).all() # Ordered for better display

    # Enrich queries with mentor_name (already done by outerjoin label, but loop ensures attribute existence)
    enriched_queries = []
    for q_obj, mentor_name in queries:
        q_obj.mentor_name = mentor_name
        enriched_queries.append(q_obj)

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
        # No tags editing for simplicity here, but you could add it similarly to submission
        db.session.commit()
        log_event(f"Query Edited by {session['username']} ({session['userid']}): {query.title}")

        # Emit SocketIO event for real-time update
        socketio.emit('query_updated', {
            'query_id': query.id,
            'action': 'edited_query', # More specific action
            'title': query.title,
            'description': query.description,
            'tags': query.tags, # Pass existing tags
            'status': query.status,
            'submitted_by_id': query.submitted_by,
            'edited_by_username': session['username']
        }, namespace='/')

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
        
        # Emit SocketIO event for real-time update
        socketio.emit('query_updated', {
            'query_id': q.id,
            'action': 'deleted_query', # More specific action
            'title': q.title,
            'submitted_by_id': q.submitted_by,
            'deleted_by_username': session['username']
        }, namespace='/')

        flash("Query deleted.", "success")
    else:
        flash("Not allowed to delete resolved queries or queries not submitted by you.", "danger")
    return redirect('/developer')

# ---------------- Mentor ----------------

# NEW: Mentor Expertise Setup Route
@routes.route('/mentor_setup_expertise', methods=['GET', 'POST'])
def mentor_setup_expertise():
    # Ensure only logged-in mentors who haven't set expertise can access this
    if 'userid' not in session or session['role'] != 'mentor':
        flash("Access denied. Please log in as a mentor.", "danger")
        return redirect('/login')

    user = User.query.filter_by(userid=session['userid']).first()

    # If expertise is already set, redirect to dashboard
    if user and user.expertise and user.expertise != '': # Check if expertise is empty string or None
        flash("Your expertise is already set. Redirecting to dashboard.", "info")
        return redirect('/mentor')

    if request.method == 'POST':
        selected_expertise = request.form.getlist('expertise')
        if not selected_expertise:
            flash("Please select at least one area of expertise.", "warning")
            return redirect('/mentor_setup_expertise')

        user.expertise = ','.join(selected_expertise)
        db.session.commit()
        log_event(f"Mentor {user.username} ({user.userid}) set expertise: {user.expertise}")
        flash("Your expertise has been saved!", "success")
        return redirect('/mentor')

    return render_template('mentor_setup_expertise.html', user=user) # Pass user object if needed for template

@routes.route('/mentor')
def mentor_dashboard(): # Renamed to avoid conflict with potential function 'mentor' in app
    if session.get('role') != 'mentor':
        flash("Mentor access only.", "danger")
        return redirect('/login')

    # Fetch queries submitted by any developer, and those assigned to current mentor
    # Also include the developer's username for display
    # We also need query tags for the mentor dashboard
    Developer = aliased(User)
    queries = db.session.query(Query, Developer.username.label('developer_name')) \
        .join(Developer, Query.submitted_by == Developer.userid) \
        .filter(
            (Query.assigned_to == None) | (Query.assigned_to == session['userid'])
        ).order_by(Query.id.desc()).all() # Order by ID for consistency

    # Enrich queries with developer_name
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
        
        # Emit SocketIO event for real-time update
        socketio.emit('query_updated', {
            'query_id': query.id,
            'action': 'accepted_by_mentor', # More specific action
            'title': query.title,
            'assigned_to': session['userid'],
            'mentor_name': session['username'],
            'status': 'In Progress',
            'tags': query.tags, # Include tags
            'developer_name': User.query.filter_by(userid=query.submitted_by).first().username if query.submitted_by else 'Unknown'
        }, namespace='/')

        flash("Accepted.", "success")
    else:
        flash("Query is already assigned.", "warning")
    return redirect('/mentor')

@routes.route('/mentor/revoke/<int:qid>', methods=['POST'])
def revoke_query(qid):
    q = Query.query.get_or_404(qid)
    if q.assigned_to == session['userid']:
        # Store revoked mentor's info before unassigning
        revoked_mentor_username = session['username'] # Or fetch from DB if needed for other dashboards

        q.assigned_to = None
        q.status = 'Open' # Changed from 'Pending' to 'Open' as it's now available again
        db.session.commit()
        log_event(f"Mentor {session['username']} ({session['userid']}) revoked query: {q.title}")
        
        # Emit SocketIO event for real-time update
        socketio.emit('query_updated', {
            'query_id': q.id,
            'action': 'revoked_by_mentor', # More specific action
            'title': q.title,
            'revoked_mentor_id': session['userid'],
            'revoked_mentor_name': revoked_mentor_username,
            'status': 'Open', # New status
            'tags': q.tags, # Include tags
            'developer_name': User.query.filter_by(userid=q.submitted_by).first().username if q.submitted_by else 'Unknown'
        }, namespace='/')

        flash("Query assignment revoked.", "info")
    else:
        flash("Unauthorized to revoke this query.", "danger")
    return redirect('/mentor')

@routes.route('/mentor/update_status/<int:query_id>', methods=['POST'])
def update_status(query_id):
    query = Query.query.get_or_404(query_id)
    # Mentors can only update status of queries assigned to them
    if query.assigned_to != session['userid']:
        flash("Unauthorized. You can only update status for queries assigned to you.", "danger")
        return redirect('/mentor')

    new_status = request.form.get('status')
    old_status = query.status
    query.status = new_status
    db.session.commit()
    log_event(f"Mentor {session['username']} ({session['userid']}) updated status from {old_status} to {new_status} for: {query.title}")
    
    # Emit SocketIO event for real-time update
    socketio.emit('query_updated', {
        'query_id': query.id,
        'action': 'status_updated_by_mentor', # More specific action
        'title': query.title,
        'old_status': old_status,
        'new_status': new_status,
        'updated_by_mentor_username': session['username'],
        'tags': query.tags, # Include tags
        'developer_name': User.query.filter_by(userid=query.submitted_by).first().username if query.submitted_by else 'Unknown',
        'assigned_to': query.assigned_to # Include current assignee
    }, namespace='/')

    flash("Status updated.", "success")
    return redirect('/mentor')

@routes.route('/mentor/solve/<int:qid>', methods=['POST'])
def solve_query(qid):
    q = Query.query.get_or_404(qid)
    if q.assigned_to != session['userid']:
        flash("Unauthorized.", "danger")
        return redirect('/mentor')
    q.solution = request.form['solution']
    q.status = 'Resolved' # Always set to Resolved when solution is submitted
    db.session.commit()
    log_event(f"Mentor {session['username']} ({session['userid']}) resolved query {q.title} with solution update.")
    
    # Emit SocketIO event for real-time update
    socketio.emit('query_updated', {
        'query_id': q.id,
        'action': 'resolved_by_mentor', # More specific action
        'title': q.title,
        'mentor_id': session['userid'],
        'mentor_name': session['username'],
        'status': 'Resolved',
        'solution_text': q.solution,
        'tags': q.tags, # Include tags
        'developer_name': User.query.filter_by(userid=q.submitted_by).first().username if q.submitted_by else 'Unknown'
    }, namespace='/')

    flash("Solution submitted and query marked as Resolved.", "success")
    return redirect('/mentor')

# ---------------- Admin ----------------

@routes.route('/admin')
def admin_dashboard(): # Renamed to avoid conflict
    if session.get('role') != 'admin':
        return redirect('/login')

    Developer = aliased(User)
    Mentor = aliased(User)

    raw_data = db.session.query(Query, Developer.username.label('developer_name'), Mentor.username.label('mentor_name')) \
        .outerjoin(Developer, Query.submitted_by == Developer.userid) \
        .outerjoin(Mentor, Query.assigned_to == Mentor.userid) \
        .order_by(Query.id.desc()).all() # Order by ID for consistency

    queries = []
    for q, dev_name, ment_name in raw_data:
        q.developer_name = dev_name
        q.mentor_name = ment_name
        queries.append(q)

    # For admin, get ALL mentors, regardless of assignment, for manual assignment dropdown
    all_mentors = User.query.filter_by(role='mentor').all()

    return render_template('admin.html', queries=queries, mentors=all_mentors) # Pass all_mentors to admin for manual assignment


@routes.route('/admin/assign/<int:query_id>', methods=['POST'])
def admin_assign_mentor(query_id):
    mentor_id = request.form['mentor_id']
    query = Query.query.get_or_404(query_id)
    
    assigned_mentor_user = User.query.filter_by(userid=mentor_id).first()
    mentor_username = assigned_mentor_user.username if assigned_mentor_user else 'Unknown Mentor'

    if query.assigned_to:
        flash("Query is already assigned. Please revoke first if you want to re-assign.", "warning")
    else:
        query.assigned_to = mentor_id
        query.status = 'In Progress'
        db.session.commit()
        log_event(f"Admin {session['username']} assigned mentor {mentor_id} to query {query.title}")
        
        # Emit SocketIO event for real-time update
        socketio.emit('query_updated', {
            'query_id': query.id,
            'action': 'assigned_by_admin',
            'title': query.title,
            'assigned_to': mentor_id,
            'mentor_name': mentor_username,
            'admin_name': session['username'],
            'status': 'In Progress',
            'tags': query.tags, # Include tags
            'developer_name': User.query.filter_by(userid=query.submitted_by).first().username if query.submitted_by else 'Unknown'
        }, namespace='/')

        flash("Mentor assigned successfully.", "success")
    return redirect('/admin')

@routes.route('/admin/revoke/<int:query_id>', methods=['POST'])
def admin_revoke_mentor(query_id):
    query = Query.query.get_or_404(query_id)
    if not query.assigned_to:
        flash("No mentor assigned to this query.", "info")
    else:
        # Store revoked mentor's ID and name before nullifying
        revoked_mentor_id = query.assigned_to 
        revoked_mentor_user = User.query.filter_by(userid=revoked_mentor_id).first()
        revoked_mentor_name = revoked_mentor_user.username if revoked_mentor_user else 'Unknown Mentor'

        log_event(f"Admin {session['username']} revoked mentor {revoked_mentor_id} from query {query.title}")
        query.assigned_to = None
        query.status = 'Open' # Query becomes 'Open' again for re-assignment
        db.session.commit()
        
        # Emit SocketIO event for real-time update
        socketio.emit('query_updated', {
            'query_id': query.id,
            'action': 'revoked_by_admin',
            'title': query.title,
            'revoked_mentor_id': revoked_mentor_id,
            'revoked_mentor_name': revoked_mentor_name,
            'admin_name': session['username'],
            'status': 'Open', # New status
            'tags': query.tags, # Include tags
            'developer_name': User.query.filter_by(userid=query.submitted_by).first().username if query.submitted_by else 'Unknown'
        }, namespace='/')

        flash("Mentor assignment revoked successfully.", "success")
    return redirect('/admin')

# ---------------- Profile Management ----------------

@routes.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    userid = session.get('userid')
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

            # Update expertise for mentors
            if user.role == 'mentor':
                selected_expertise = request.form.getlist('expertise') # getlist for multi-select
                user.expertise = ','.join(selected_expertise) # Join into a comma-separated string

            db.session.commit()
            log_event(f"Profile Updated: {user.username} (ID: {user.userid}, Role: {user.role})")
            if session['username'] != new_username:
                session['username'] = new_username
            
            flash("Profile updated successfully.", "success")
            return redirect(f"/{user.role.lower()}")
    except Exception as e:
        db.session.rollback()
        print("Error in update_profile:", e)
        import traceback
        print(traceback.format_exc())
        flash("An error occurred. Please try again later.", "danger")
    
    # For GET request, render the template
    return render_template('update_profile.html', user=user)

@routes.route('/delete_account', methods=['POST'])
def delete_account():
    if 'userid' not in session:
        return redirect('/login')

    user = User.query.filter_by(userid=session['userid']).first()

    if user: # Ensure user exists before trying to delete
        # Also delete user's queries where they were submitter or assignee
        Query.query.filter((Query.submitted_by == user.userid) | (Query.assigned_to == user.userid)).delete(synchronize_session=False) # synchronize_session=False for delete() on a query

        db.session.delete(user)
        db.session.commit()

        log_event(f"Account Deleted: {user.username} (ID: {user.userid}, Role: {user.role})")
        session.clear()
        flash("Your account has been deleted.", "info")
    else:
        flash("User account not found.", "danger")
    return redirect('/')