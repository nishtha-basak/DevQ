from devq_app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    userid = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)


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

    def __repr__(self):
        return f"<Query {self.id} - {self.title}>"
