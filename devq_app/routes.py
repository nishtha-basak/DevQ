from flask import Blueprint, render_template, request, redirect, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import aliased
from devq_app import db, socketio # socketio is imported globally
from devq_app.models import User, Query
from devq_app.logger import log_event
# Import the new scheduler helper function
from devq_app.scheduler import find_and_assign_single_query

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
        role = request.form['role'].lower()

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)

        try:
            db.session.add(new_user)
            db.session.commit()

            role_suffix = ROLE_SUFFIX.get(role, 'X')
            new_user.userid = f"{new_user.id}{role_suffix}"
            db.session.commit()

            flash(f"Account created successfully! Your User ID is: {new_user.userid}", "success")
            log_event(f"New user signed up: {new_user.username} (ID: {new_user.userid}) as {new_user.role}")
            return redirect('/login')

        except Exception as e:
            db.session.rollback()
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
        role = request.form['role'].lower()

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
    developer = User.query.filter_by(userid=developer_id).first()

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        # Tags from the hidden input for the custom dropdown
        tags_raw_input = request.form.get('tags', '') # Get the single string
        final_tags_string = tags_raw_input # This is already comma-separated

        new_query = Query(
            title=title,
            description=description,
            tags=final_tags_string,
            submitted_by=developer_id,
            status='Open'
        )
        db.session.add(new_query)
        db.session.commit()
        flash("Query submitted successfully!", "success")
        log_event(f"Query submitted by {developer.username} ({developer.userid}): '{title}' with tags: {final_tags_string}")

        socketio.emit('query_updated', {
            'query_id': new_query.id,
            'action': 'new_query',
            'title': new_query.title,
            'description': new_query.description,
            'tags': new_query.tags,
            'status': new_query.status,
            'submitted_by_id': new_query.submitted_by,
            'developer_name': developer.username
        }, namespace='/')

        return redirect('/developer')

    queries = db.session.query(Query, User.username.label('mentor_name')) \
        .outerjoin(User, Query.assigned_to == User.userid) \
        .filter(Query.submitted_by == developer_id).order_by(Query.id.desc()).all()

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
    
    is_assigned = query.assigned_to is not None and query.assigned_to != ''

    if request.method == 'POST':
        query.title = request.form['title']
        query.description = request.form['description']
        
        if not is_assigned: # Only update tags if not assigned
            tags_raw_input = request.form.get('tags', '')
            query.tags = tags_raw_input
        else:
            # If assigned, and developer attempts to send tag data (though UI prevents it)
            # we ignore tag changes as per requirement.
            pass 

        db.session.commit()
        log_event(f"Query Edited by {session['username']} ({session['userid']}): {query.title}. Assigned: {is_assigned}")

        socketio.emit('query_updated', {
            'query_id': query.id,
            'action': 'edited_query',
            'title': query.title,
            'description': query.description,
            'tags': query.tags,
            'status': query.status,
            'submitted_by_id': query.submitted_by,
            'edited_by_username': session['username'],
            'assigned_to_id': query.assigned_to
        }, namespace='/')

        flash("Query updated.", "success")
        return redirect('/developer')
    
    return render_template('edit_query.html', query=query, is_assigned=is_assigned)

@routes.route('/developer/delete/<int:qid>', methods=['POST'])
def delete_query(qid):
    q = Query.query.get_or_404(qid)
    if session['userid'] != q.submitted_by:
        flash("Unauthorized. You can only delete queries you have submitted.", "danger")
        return redirect('/developer')

    # Allow deletion regardless of assignment/status
    log_event(f"Query Deleted by {session['username']} ({session['userid']}): {q.title}")
    db.session.delete(q)
    db.session.commit()
    
    socketio.emit('query_updated', {
        'query_id': q.id,
        'action': 'deleted_query',
        'title': q.title,
        'submitted_by_id': q.submitted_by,
        'deleted_by_username': session['username']
    }, namespace='/')

    flash("Query deleted successfully.", "success")
    return redirect('/developer')

# ---------------- Mentor ----------------

@routes.route('/mentor_setup_expertise', methods=['GET', 'POST'])
def mentor_setup_expertise():
    if 'userid' not in session or session['role'] != 'mentor':
        flash("Access denied. Please log in as a mentor.", "danger")
        return redirect('/login')

    user = User.query.filter_by(userid=session['userid']).first()

    if user and user.expertise and user.expertise != '':
        flash("Your expertise is already set. Redirecting to dashboard.", "info")
        return redirect('/mentor')

    if request.method == 'POST':
        # Expertise from the hidden input for the custom dropdown
        expertise_raw_input = request.form.get('expertise', '')
        final_expertise_string = expertise_raw_input # This is already comma-separated

        if not final_expertise_string:
            flash("Please select at least one area of expertise.", "warning")
            return redirect('/mentor_setup_expertise')

        user.expertise = final_expertise_string
        db.session.commit()
        log_event(f"Mentor {user.username} ({user.userid}) set expertise: {user.expertise}")
        flash("Your expertise has been saved!", "success")
        return redirect('/mentor')

    return render_template('mentor_expertise_setup.html', user=user)

@routes.route('/mentor')
def mentor_dashboard():
    if session.get('role') != 'mentor':
        flash("Mentor access only.", "danger")
        return redirect('/login')

    Developer = aliased(User)
    queries = db.session.query(Query, Developer.username.label('developer_name')) \
        .join(Developer, Query.submitted_by == Developer.userid) \
        .filter(
            (Query.assigned_to == None) | (Query.assigned_to == session['userid'])
        ).order_by(Query.id.desc()).all()

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
        
        socketio.emit('query_updated', {
            'query_id': query.id,
            'action': 'accepted_by_mentor',
            'title': query.title,
            'assigned_to': session['userid'],
            'mentor_name': session['username'],
            'status': 'In Progress',
            'tags': query.tags,
            'developer_name': User.query.filter_by(userid=query.submitted_by).first().username if query.submitted_by else 'Unknown'
        }, namespace='/')

        flash("Accepted.", "success")
    else:
        flash("Query is already assigned.", "warning")
    return redirect('/mentor')

@routes.route('/mentor/revoke/<int:qid>', methods=['POST'])
def revoke_query(qid):
    q = Query.query.get_or_404(qid)
    current_mentor_id = session['userid']
    current_mentor_username = session['username']

    if q.assigned_to != current_mentor_id:
        flash("Unauthorized to revoke this query.", "danger")
        return redirect('/mentor')

    # Revoke initially
    q.assigned_to = None
    q.status = 'Open' # Query becomes 'Open' again for re-assignment
    db.session.commit()
    log_event(f"Mentor {current_mentor_username} ({current_mentor_id}) revoked query: {q.title}. Now attempting re-assignment.")

    # Attempt to re-assign immediately to another eligible mentor
    # The scheduler function finds AND assigns, committing changes internally.
    reassigned_mentor_id = find_and_assign_single_query(q.id, exclude_mentor_id=current_mentor_id)

    if reassigned_mentor_id:
        # If successfully reassigned to another mentor (done within find_and_assign_single_query)
        # Re-fetch query to get its updated state for socket emit
        db.session.refresh(q) 
        new_mentor_user = User.query.filter_by(userid=reassigned_mentor_id).first()
        new_mentor_name = new_mentor_user.username if new_mentor_user else 'Unknown Mentor'
        
        flash(f"Query assignment revoked. Successfully reassigned to {new_mentor_name}.", "info")
        log_event(f"Query {q.id} reassigned to {new_mentor_name} after {current_mentor_username} revoked.")

        socketio.emit('query_updated', {
            'query_id': q.id,
            'action': 'reassigned_after_revocation',
            'title': q.title,
            'assigned_to': q.assigned_to,
            'mentor_name': new_mentor_name,
            'status': q.status,
            'tags': q.tags,
            'developer_name': User.query.filter_by(userid=q.submitted_by).first().username if q.submitted_by else 'Unknown'
        }, namespace='/')
    else:
        # If no other eligible mentor found, re-assign back to the original mentor
        q.assigned_to = current_mentor_id
        q.status = 'In Progress' # Put it back in progress for the original mentor
        db.session.commit() # Commit this re-assignment back to original mentor
        flash("No other eligible mentor could be assigned. Query reassigned back to you.", "warning")
        log_event(f"Query {q.id} reassigned BACK to {current_mentor_username} as no other eligible mentor found.")

        # Re-fetch query to get its updated state for socket emit
        db.session.refresh(q)
        socketio.emit('query_updated', {
            'query_id': q.id,
            'action': 'reassigned_back_to_original_mentor',
            'title': q.title,
            'assigned_to': q.assigned_to,
            'mentor_name': current_mentor_username,
            'status': q.status,
            'tags': q.tags,
            'developer_name': User.query.filter_by(userid=q.submitted_by).first().username if q.submitted_by else 'Unknown'
        }, namespace='/')
        
    return redirect('/mentor')

@routes.route('/mentor/update_status/<int:query_id>', methods=['POST'])
def update_status(query_id):
    query = Query.query.get_or_404(query_id)
    if query.assigned_to != session['userid']:
        flash("Unauthorized. You can only update status for queries assigned to you.", "danger")
        return redirect('/mentor')

    new_status = request.form.get('status')
    old_status = query.status
    query.status = new_status
    db.session.commit()
    log_event(f"Mentor {session['username']} ({session['userid']}) updated status from {old_status} to {new_status} for: {query.title}")
    
    socketio.emit('query_updated', {
        'query_id': query.id,
        'action': 'status_updated_by_mentor',
        'title': query.title,
        'old_status': old_status,
        'new_status': new_status,
        'updated_by_mentor_username': session['username'],
        'tags': query.tags,
        'developer_name': User.query.filter_by(userid=query.submitted_by).first().username if query.submitted_by else 'Unknown',
        'assigned_to': query.assigned_to
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
    q.status = 'Resolved'
    db.session.commit()
    log_event(f"Mentor {session['username']} ({session['userid']}) resolved query {q.title} with solution update.")
    
    socketio.emit('query_updated', {
        'query_id': q.id,
        'action': 'resolved_by_mentor',
        'title': q.title,
        'mentor_id': session['userid'],
        'mentor_name': session['username'],
        'status': 'Resolved',
        'solution_text': q.solution,
        'tags': q.tags,
        'developer_name': User.query.filter_by(userid=q.submitted_by).first().username if q.submitted_by else 'Unknown'
    }, namespace='/')

    flash("Solution submitted and query marked as Resolved.", "success")
    return redirect('/mentor')

# ---------------- Admin ----------------

@routes.route('/admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect('/login')

    Developer = aliased(User)
    Mentor = aliased(User)

    raw_data = db.session.query(Query, Developer.username.label('developer_name'), Mentor.username.label('mentor_name')) \
        .outerjoin(Developer, Query.submitted_by == Developer.userid) \
        .outerjoin(Mentor, Query.assigned_to == Mentor.userid) \
        .order_by(Query.id.desc()).all()

    queries = []
    for q, dev_name, ment_name in raw_data:
        q.developer_name = dev_name
        q.mentor_name = ment_name
        queries.append(q)

    all_mentors = User.query.filter_by(role='mentor').all()

    return render_template('admin.html', queries=queries, mentors=all_mentors)


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
        
        socketio.emit('query_updated', {
            'query_id': query.id,
            'action': 'assigned_by_admin',
            'title': query.title,
            'assigned_to': mentor_id,
            'mentor_name': mentor_username,
            'admin_name': session['username'],
            'status': 'In Progress',
            'tags': query.tags,
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
        revoked_mentor_id = query.assigned_to 
        revoked_mentor_user = User.query.filter_by(userid=revoked_mentor_id).first()
        revoked_mentor_name = revoked_mentor_user.username if revoked_mentor_user else 'Unknown Mentor'

        log_event(f"Admin {session['username']} revoked mentor {revoked_mentor_id} from query {query.title}")
        query.assigned_to = None
        query.status = 'Open'
        db.session.commit()
        
        socketio.emit('query_updated', {
            'query_id': query.id,
            'action': 'revoked_by_admin',
            'title': query.title,
            'revoked_mentor_id': revoked_mentor_id,
            'revoked_mentor_name': revoked_mentor_name,
            'admin_name': session['username'],
            'status': 'Open',
            'tags': query.tags,
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

            if user.role == 'mentor':
                selected_expertise_str = request.form.get('expertise', '')
                user.expertise = selected_expertise_str 

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
    
    return render_template('update_profile.html', user=user)

@routes.route('/delete_account', methods=['POST'])
def delete_account():
    if 'userid' not in session:
        return redirect('/login')

    user = User.query.filter_by(userid=session['userid']).first()

    if user:
        Query.query.filter((Query.submitted_by == user.userid) | (Query.assigned_to == user.userid)).delete(synchronize_session=False)

        db.session.delete(user)
        db.session.commit()

        log_event(f"Account Deleted: {user.username} (ID: {user.userid}, Role: {user.role})")
        session.clear()
        flash("Your account has been deleted.", "info")
    else:
        flash("User account not found.", "danger")
    return redirect('/')