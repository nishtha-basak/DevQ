from flask import render_template, request, redirect, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from devq_app import  db
from devq_app.models import Query, User

from flask import Blueprint, render_template, request, redirect, url_for, flash, session,current_app as app

ROLE_SUFFIX = {
    'developer': 'D',
    'mentor': 'M',
    'admin': 'A'
}

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

        flash(f"Welcome, {user.username} ({user.role.title()})!", "success")

        role_redirects = {
            'developer': '/developer',
            'mentor': '/mentor',
            'admin': '/admin'
        }

        return redirect(role_redirects.get(role.lower(), '/'))

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'userid' not in session:
        flash("Please login first.", "warning")
        return redirect('/login')
    return render_template('dashboard.html')


from sqlalchemy.orm import aliased

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
        flash("Query submitted successfully!", "success")
        return redirect('/developer')

    Mentor = aliased(User)
    queries = db.session.query(
        Query,
        Mentor.username.label('mentor_name')
    ).outerjoin(Mentor, Query.assigned_to == Mentor.userid
    ).filter(Query.submitted_by == session['userid']).all()

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
        query.title = request.form['title']
        query.description = request.form['description']
        db.session.commit()
        flash("Query updated successfully.", "success")
        return redirect('/developer')

    return render_template('edit_query.html', query=query)

@app.route('/developer/delete/<int:qid>', methods=['POST'])
def delete_query(qid):
    q = Query.query.get_or_404(qid)
    if q.submitted_by == session['userid'] and q.status != 'Resolved':
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

    # Fetch queries either unassigned or assigned to the current mentor
    queries = Query.query.filter((Query.assigned_to==None)|(Query.assigned_to==session['userid'])).all()
    for q in queries:
        dev = User.query.filter_by(userid=q.submitted_by).first()
        q.dev_name = dev.username
    return render_template('mentor.html', queries=queries)
@app.route('/mentor/revoke/<int:qid>', methods=['POST'])
def revoke_query(qid):
    q = Query.query.get_or_404(qid)
    if q.assigned_to == session['userid'] and q.status != 'Resolved':
        q.assigned_to = None
        q.status = 'Pending'
        db.session.commit()
        flash("Query revoked. Now unassigned.", "info")
    else:
        flash("Cannot revoke.", "danger")
    return redirect('/mentor')

@app.route('/mentor/accept/<int:query_id>', methods=['POST'])
def accept_query(query_id):
    if 'userid' not in session or session.get('role') != 'mentor':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    query = Query.query.get(query_id)
    if query:
        query.assigned_to = session['userid']
        query.status = 'In Progress'
        db.session.commit()
        flash("Query accepted and assigned to you.", "success")
    else:
        flash("Query not found.", "danger")

    return redirect('/mentor')

@app.route('/mentor/update_status/<int:query_id>', methods=['POST'])
def update_status(query_id):
    if 'userid' not in session or session.get('role') != 'mentor':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    new_status = request.form.get('status')
    query = Query.query.get(query_id)
    if query and query.assigned_to == session['userid']:
        query.status = new_status
        db.session.commit()
        flash("Status updated successfully.", "success")
    else:
        flash("Query not found or unauthorized.", "danger")

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
    flash("Solution submitted.", "success")
    return redirect('/mentor')

from sqlalchemy.orm import aliased

@app.route('/admin')
def admin():
    if session.get('role') != 'admin':
        return redirect('/login')

    Developer = aliased(User)
    Mentor = aliased(User)

    raw_query_data = db.session.query(
        Query,
        Developer.username.label('developer_name'),
        Mentor.username.label('mentor_name')
    ).outerjoin(Developer, Query.submitted_by == Developer.userid
    ).outerjoin(Mentor, Query.assigned_to == Mentor.userid
    ).all()

    # Format: make `query` have `developer_name` and `mentor_name` as attributes
    queries = []
    for query, dev_name, ment_name in raw_query_data:
        query.developer_name = dev_name
        query.mentor_name = ment_name
        queries.append(query)

    # All mentor user objects
    all_mentors = User.query.filter_by(role='mentor').all()

    # Mentors currently assigned to at least one query
    assigned_mentor_ids = [q.assigned_to for q in Query.query.filter(Query.assigned_to.isnot(None)).all()]
    free_mentors = [mentor for mentor in all_mentors if mentor.userid not in assigned_mentor_ids]

    return render_template('admin.html', queries=queries, mentors=free_mentors)

@app.route('/admin/assign/<int:query_id>', methods=['POST'])
def assign_mentor(query_id):
    if 'userid' not in session or session['role'].lower() != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    mentor_id = request.form['mentor_id']
    query = Query.query.get(query_id)

    already_assigned = Query.query.filter_by(assigned_to=mentor_id).first()

    if not query:
        flash("Query not found.", "danger")
    elif query.assigned_to:
        flash("This query is already assigned to a mentor.", "warning")
    elif already_assigned:
        flash("Mentor already assigned to another query.", "danger")
    else:
        query.assigned_to = mentor_id
        query.status = 'In Progress'
        db.session.commit()
        flash("Mentor assigned successfully.", "success")

    return redirect('/admin')
@app.route('/admin/revoke/<int:query_id>', methods=['POST'])
def revoke_mentor(query_id):
    if 'userid' not in session or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect('/login')

    query = Query.query.get(query_id)
    if not query:
        flash("Query not found.", "danger")
    elif not query.assigned_to:
        flash("No mentor is currently assigned to this query.", "info")
    else:
        query.assigned_to = None
        query.status = 'Pending'
        db.session.commit()
        flash("Mentor assignment revoked successfully.", "success")

    return redirect('/admin')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect('/')