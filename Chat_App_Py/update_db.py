import sqlite3
import os

# Delete existing database if it exists
if os.path.exists('chatapp.db'):
    os.remove('chatapp.db')
    print("Deleted existing database")

print("Database will be recreated when you restart your application")