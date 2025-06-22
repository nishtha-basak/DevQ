from flask import render_template, request, redirect, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from devq_app import db
from devq_app.models import Query, User
from devq_app.logger import log_event
from flask import Blueprint, url_for, current_app as app
from sqlalchemy.orm import aliased
from datetime import datetime

ROLE_SUFFIX = {
    'developer': 'D',
    'mentor': 'M',
    'admin': 'A'
}

def get_user_details(user_id):
    user = User.query.filter_by(userid=user_id).first()
    if not user:
        return f"Unknown UserID: {user_id}"
    return f"[{user.userid}] {user.username} ({user.role})"

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        next_id = (User.query.count() or 0) + 101
        role_suffix = ROLE_SUFFIX.get(role.lower(), 'X')
        userid = f"{next_id}{role_suffix}"

        if User.query.filter_by(userid=userid).first():
            flash("Generated User ID already exists. Please try again.", "danger")
            return redirect('/signup')

        hashed_password = generate_password_hash(password)
        user = User(username=username, userid=userid, password=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()

        log_event(f"New user registered: {get_user_details(userid)}")

        flash(f"Registration successful! Your User ID is {userid}", "success")
        return redirect('/login')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        userid = request.form['userid'].strip()
        password = request.form['password']
        role = request.form['role']

        user = User.query.filter_by(userid=userid).first()

        if not user:
            flash("No such user. Please sign up first.", "danger")
            return redirect('/signup')

        if user.role != role:
            flash(f"Incorrect role selected. You are registered as a {user.role.title()}.", "warning")
            return redirect('/login')

        if not check_password_hash(user.password, password):
            flash("Incorrect password.", "danger")
            return redirect('/login')

        session.clear()
        session['userid'] = user.userid
        session['username'] = user.username
        session['role'] = user.role

        log_event(f"{get_user_details(user.userid)} logged in.")

        flash(f"Welcome, {user.username} ({user.role.title()})!", "success")

        return redirect({
            'developer': '/developer',
            'mentor': '/mentor',
            'admin': '/admin'
        }.get(role.lower(), '/'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    user_info = get_user_details(session.get('userid'))
    session.clear()
    log_event(f"{user_info} logged out.")
    flash("You have been logged out.", "info")
    return redirect('/')

@app.route('/developer', methods=['GET', 'POST'])
def developer():
    if 'userid' not in session:
        flash("Please login first.", "warning")
        return redirect('/login')

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        submitted_by = session['userid']
        new_query = Query(title=title, description=description, submitted_by=submitted_by)
        db.session.add(new_query)
        db.session.commit()

        log_event(f"Query submitted by {get_user_details(submitted_by)}: Title='{title}', Description='{description}'")

        flash("Query submitted successfully!", "success")
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

@app.route('/developer/edit/<int:qid>', methods=['GET', 'POST'])
def edit_query(qid):
    if 'userid' not in session or session['role'] != 'developer':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    query = Query.query.get_or_404(qid)

    if query.submitted_by != session['userid']:
        flash("You can only edit your own queries.", "danger")
        return redirect('/developer')

    if query.status == 'Resolved':
        flash("You can't edit a resolved query.", "warning")
        return redirect('/developer')

    if request.method == 'POST':
        old_title, old_desc = query.title, query.description
        query.title = request.form['title']
        query.description = request.form['description']
        db.session.commit()

        log_event(f"{get_user_details(session['userid'])} edited query {qid}.\n"
                  f"Old Title: '{old_title}', New Title: '{query.title}'\n"
                  f"Old Desc: '{old_desc}', New Desc: '{query.description}'")

        flash("Query updated successfully.", "success")
        return redirect('/developer')

    return render_template('edit_query.html', query=query)

@app.route('/developer/delete/<int:qid>', methods=['POST'])
def delete_query(qid):
    q = Query.query.get_or_404(qid)
    if q.submitted_by == session['userid'] and q.status != 'Resolved':
        log_event(f"{get_user_details(session['userid'])} deleted query {qid}: Title='{q.title}', Description='{q.description}'")
        db.session.delete(q)
        db.session.commit()
        flash("Query deleted.", "success")
    else:
        flash("Cannot delete this query.", "danger")
    return redirect('/developer')

@app.route('/mentor')
def mentor():
    if 'userid' not in session or session.get('role') != 'mentor':
        flash("Access restricted to mentors only.", "danger")
        return redirect('/login')

    queries = Query.query.filter((Query.assigned_to == None) | (Query.assigned_to == session['userid'])).all()
    for q in queries:
        dev = User.query.filter_by(userid=q.submitted_by).first()
        q.dev_name = dev.username if dev else 'Unknown'
    return render_template('mentor.html', queries=queries)

@app.route('/mentor/accept/<int:query_id>', methods=['POST'])
def accept_query(query_id):
    query = Query.query.get_or_404(query_id)
    if 'userid' in session and session['role'] == 'mentor':
        query.assigned_to = session['userid']
        query.status = 'In Progress'
        db.session.commit()
        log_event(f"{get_user_details(session['userid'])} accepted query {query_id}: Title='{query.title}', Desc='{query.description}'")
        flash("Query accepted and assigned to you.", "success")
    else:
        flash("Unauthorized access.", "danger")
    return redirect('/mentor')

@app.route('/mentor/revoke/<int:qid>', methods=['POST'])
def revoke_query(qid):
    q = Query.query.get_or_404(qid)
    if q.assigned_to == session['userid'] and q.status != 'Resolved':
        log_event(f"{get_user_details(session['userid'])} revoked query {qid}: Title='{q.title}'")
        q.assigned_to = None
        q.status = 'Pending'
        db.session.commit()
        flash("Query revoked. Now unassigned.", "info")
    else:
        flash("Cannot revoke.", "danger")
    return redirect('/mentor')

@app.route('/mentor/update_status/<int:query_id>', methods=['POST'])
def update_status(query_id):
    new_status = request.form.get('status')
    query = Query.query.get_or_404(query_id)
    if query.assigned_to == session['userid']:
        old_status = query.status
        query.status = new_status
        db.session.commit()
        mentor = User.query.filter_by(userid=session['userid']).first()
        log_event(
            f"Query status updated by Mentor {mentor.username} (ID: {mentor.userid}, Role: {mentor.role}) "
            f"from '{old_status}' to '{new_status}' for query ID {query.id} titled '{query.title}', "
            f"Description: '{query.description}' at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        flash("Status updated successfully.", "success")
    else:
        flash("Unauthorized.", "danger")
    return redirect('/mentor')

@app.route('/mentor/solve/<int:qid>', methods=['POST'])
def solve_query(qid):
    q = Query.query.get_or_404(qid)
    if q.assigned_to != session['userid']:
        flash("Unauthorized.", "danger")
        return redirect('/mentor')
    q.solution = request.form['solution']
    q.status = 'Resolved'
    db.session.commit()
    log_event(f"{get_user_details(session['userid'])} resolved query {qid}: Title='{q.title}', Solution='{q.solution}'")
    flash("Solution submitted.", "success")
    return redirect('/mentor')

@app.route('/admin')
def admin():
    if session.get('role') != 'admin':
        return redirect('/login')

    Developer = aliased(User)
    Mentor = aliased(User)

    raw_query_data = db.session.query(Query, Developer.username.label('developer_name'), Mentor.username.label('mentor_name')) \
        .outerjoin(Developer, Query.submitted_by == Developer.userid) \
        .outerjoin(Mentor, Query.assigned_to == Mentor.userid).all()

    queries = []
    for query, dev_name, ment_name in raw_query_data:
        query.developer_name = dev_name
        query.mentor_name = ment_name
        queries.append(query)

    all_mentors = User.query.filter_by(role='mentor').all()
    assigned_ids = [q.assigned_to for q in Query.query.filter(Query.assigned_to.isnot(None)).all()]
    free_mentors = [m for m in all_mentors if m.userid not in assigned_ids]

    return render_template('admin.html', queries=queries, mentors=free_mentors)

@app.route('/admin/assign/<int:query_id>', methods=['POST'])
def assign_mentor(query_id):
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    mentor_id = request.form['mentor_id']
    query = Query.query.get_or_404(query_id)
    already_assigned = Query.query.filter_by(assigned_to=mentor_id).first()

    if query.assigned_to:
        flash("This query is already assigned.", "warning")
    elif already_assigned:
        flash("Mentor already assigned to another query.", "danger")
    else:
        query.assigned_to = mentor_id
        query.status = 'In Progress'
        db.session.commit()
        log_event(f"{get_user_details(session['userid'])} assigned mentor {get_user_details(mentor_id)} to query {query_id}")
        flash("Mentor assigned successfully.", "success")

    return redirect('/admin')

@app.route('/admin/revoke/<int:query_id>', methods=['POST'])
def revoke_mentor(query_id):
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    query = Query.query.get_or_404(query_id)
    if not query.assigned_to:
        flash("No mentor assigned.", "info")
    else:
        log_event(f"{get_user_details(session['userid'])} revoked mentor {get_user_details(query.assigned_to)} from query {query_id}")
        query.assigned_to = None
        query.status = 'Pending'
        db.session.commit()
        flash("Mentor assignment revoked.", "success")

    return redirect('/admin')
