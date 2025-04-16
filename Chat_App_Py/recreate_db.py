# recreate_db.py
from app import app, db

with app.app_context():
    db.drop_all()  # This is redundant since we deleted the file, but good practice
    db.create_all()  # Create all tables with new schema
    print("Database recreated successfully!")