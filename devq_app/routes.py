from flask import Blueprint, render_template, request, redirect, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import aliased
from devq_app import db, socketio
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
    log_event(f"Logout: {user} ({role})")
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
        socketio.emit('new_query', {'title': title})
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
    if request.method == 'POST':
        query.title = request.form['title']
        query.description = request.form['description']
        db.session.commit()
        log_event(f"Query Edited by {session['username']} ({session['userid']}): {query.title}")
        flash("Query updated.", "success")
        return redirect('/developer')
    return render_template('edit_query.html', query=query)

@routes.route('/developer/delete/<int:qid>', methods=['POST'])
def delete_query(qid):
    q = Query.query.get_or_404(qid)
    if session['userid'] == q.submitted_by and q.status != 'Resolved':
        db.session.delete(q)
        db.session.commit()
        log_event(f"Query Deleted by {session['username']} ({session['userid']}): {q.title}")
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

    queries = Query.query.filter(
        (Query.assigned_to == None) | (Query.assigned_to == session['userid'])
    ).all()
    for q in queries:
        dev = User.query.filter_by(userid=q.submitted_by).first()
        q.dev_name = dev.username
    return render_template('mentor.html', queries=queries)

@routes.route('/mentor/accept/<int:query_id>', methods=['POST'])
def accept_query(query_id):
    query = Query.query.get_or_404(query_id)
    if query.assigned_to is None:
        query.assigned_to = session['userid']
        query.status = 'In Progress'
        db.session.commit()
        log_event(f"Query Accepted by Mentor {session['username']} ({session['userid']}): {query.title}")
        socketio.emit('status_update', {'title': query.title, 'status': 'In Progress'})
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
        socketio.emit('status_update', {'title': q.title, 'status': 'Pending'})
        flash("Revoked.", "info")
    else:
        flash("Unauthorized.", "danger")
    return redirect('/mentor')

@routes.route('/mentor/update_status/<int:query_id>', methods=['POST'])
def update_status(query_id):
    query = Query.query.get_or_404(query_id)
    if query.assigned_to != session['userid']:
        flash("Unauthorized.", "danger")
        return redirect('/mentor')

    new_status = request.form.get('status')
    old_status = query.status
    query.status = new_status
    db.session.commit()
    log_event(f"Mentor {session['username']} ({session['userid']}) updated status from {old_status} to {new_status} for: {query.title}")
    socketio.emit('status_update', {'title': query.title, 'status': new_status})
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
    socketio.emit('status_update', {'title': q.title, 'status': 'Resolved'})
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
    assigned_ids = [q.assigned_to for q in Query.query.filter(Query.assigned_to.isnot(None)).all()]
    free_mentors = [m for m in all_mentors if m.userid not in assigned_ids]

    return render_template('admin.html', queries=queries, mentors=free_mentors)

@routes.route('/admin/assign/<int:query_id>', methods=['POST'])
def assign_mentor(query_id):
    mentor_id = request.form['mentor_id']
    query = Query.query.get_or_404(query_id)
    if query.assigned_to:
        flash("Already assigned.", "warning")
    else:
        query.assigned_to = mentor_id
        query.status = 'In Progress'
        db.session.commit()
        log_event(f"Admin {session['username']} assigned mentor {mentor_id} to query {query.title}")
        socketio.emit('status_update', {'title': query.title, 'status': 'In Progress'})
        flash("Mentor assigned.", "success")
    return redirect('/admin')

@routes.route('/admin/revoke/<int:query_id>', methods=['POST'])
def revoke_mentor(query_id):
    query = Query.query.get_or_404(query_id)
    if not query.assigned_to:
        flash("No mentor assigned.", "info")
    else:
        log_event(f"Admin {session['username']} revoked mentor {query.assigned_to} from {query.title}")
        query.assigned_to = None
        query.status = 'Pending'
        db.session.commit()
        socketio.emit('status_update', {'title': query.title, 'status': 'Pending'})
        flash("Revoked.", "success")
    return redirect('/admin')
