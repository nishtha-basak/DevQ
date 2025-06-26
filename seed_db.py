# seed_db.py

from devq_app import create_app, db # Import create_app and db instance
from devq_app.models import User, Query # Import your User and Query models
from werkzeug.security import generate_password_hash # For hashing passwords
import os

print("--- Starting Database Seeding ---")

# Create Flask app instance
app = create_app()

# Manually push an application context
# This is crucial for running Flask-SQLAlchemy operations outside of a request
with app.app_context():
    print("Creating all database tables (if they don't exist)...")
    db.create_all() # This ensures tables are created with the latest schema

    # Clear existing users and queries if any (redundant if you just ran DROP TABLE)
    print("Clearing existing users and queries...")
    Query.query.delete()
    User.query.delete()
    db.session.commit()
    print("Existing data cleared.")

    ROLE_SUFFIX = {
        'developer': 'D',
        'C': 'C', # Default suffix for new roles
        'mentor': 'M',
        'admin': 'A'
    }
    
    users_to_create = []
    
    # --- Create 5 Developers ---
    for i in range(1, 6):
        username = f"DevUser{i}"
        password = "password" # Simple password for testing
        role = "developer"
        hashed_password = generate_password_hash(password)
        # We need to get the user ID after the first commit for the two-stage process
        # so we'll create temporary User objects and populate userid later.
        users_to_create.append({'username': username, 'password': hashed_password, 'role': role})
        
    # --- Create 5 Mentors ---
    # Give them some diverse expertise for testing tag matching
    mentor_expertises = [
        "Frontend,Backend",
        "Database,DevOps",
        "Bug,Performance",
        "Security,Question",
        "Environment Setup,Backend" # Mix of two tags
    ]
    for i in range(1, 6):
        username = f"MentorUser{i}"
        password = "password"
        role = "mentor"
        hashed_password = generate_password_hash(password)
        expertise = mentor_expertises[i-1] if i <= len(mentor_expertises) else ""
        users_to_create.append({'username': username, 'password': hashed_password, 'role': role, 'expertise': expertise})

    # --- Create 5 Admins ---
    for i in range(1, 6):
        username = f"AdminUser{i}"
        password = "password"
        role = "admin"
        hashed_password = generate_password_hash(password)
        users_to_create.append({'username': username, 'password': hashed_password, 'role': role})

    print(f"Attempting to add {len(users_to_create)} users...")

    created_users_details = []
    for user_data in users_to_create:
        try:
            # First commit to get the auto-assigned 'id'
            user = User(
                username=user_data['username'],
                password=user_data['password'],
                role=user_data['role'],
                expertise=user_data.get('expertise', '') # Will be empty string for non-mentors
            )
            db.session.add(user)
            db.session.commit() # Commit to get 'user.id'

            # Generate custom userid using the database-assigned 'id'
            role_suffix = ROLE_SUFFIX.get(user_data['role'], 'X')
            user.userid = f"{user.id}{role_suffix}"

            # Second commit to save the generated userid
            db.session.commit() # Update the userid

            created_users_details.append({
                'username': user.username,
                'userid': user.userid,
                'role': user.role,
                'expertise': user.expertise,
                'password': "password" # For display purposes only, do not store plain passwords
            })
            print(f"Added {user.role}: {user.username} (ID: {user.userid})")

        except Exception as e:
            db.session.rollback()
            print(f"Error creating user {user_data['username']}: {e}")
            import traceback
            traceback.print_exc()

    print("\n--- Users Created ---")
    print("{:<15} {:<15} {:<10} {:<30} {:<10}".format("Username", "UserID", "Role", "Expertise", "Password"))
    print("-" * 85)
    for user_detail in created_users_details:
        print("{:<15} {:<15} {:<10} {:<30} {:<10}".format(
            user_detail['username'],
            user_detail['userid'],
            user_detail['role'].title(),
            user_detail['expertise'],
            user_detail['password']
        ))

    print("\n--- Database Seeding Complete ---")
    print("Please use the generated User IDs and the password 'password' to log in.")