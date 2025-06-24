from devq_app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    userid = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    

    #Define relationships
    queries_submitted = db.relationship('Query', back_populates='submitter', foreign_keys='Query.submitted_by')
    queries_assigned = db.relationship('Query', back_populates='assignee', foreign_keys='Query.assigned_to')


class Query(db.Model):
    __tablename__ = 'query'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    
    # The User ID of the Developer who submitted the query
    submitted_by = db.Column(db.String(10), db.ForeignKey('user.userid'), nullable=False)

    # The User ID of the Mentor who is assigned
    assigned_to = db.Column(db.String(10), db.ForeignKey('user.userid'), nullable=True)
    
    status = db.Column(db.String(20), default='Open')
    solution = db.Column(db.Text, nullable=True)  # store solution text

    # Define relationships
    submitter = db.relationship('User', back_populates='queries_submitted', foreign_keys='Query.submitted_by')
    assignee = db.relationship('User', back_populates='queries_assigned', foreign_keys='Query.assigned_to') 

    def __repr__(self):
        return f"<Query {self.id} - {self.title}>"
