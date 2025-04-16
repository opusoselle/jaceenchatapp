from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import uuid
import base64
import mimetypes

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chatapp.db'  
app.config['UPLOAD_FOLDER'] = 'static/uploads/profile_pics'
app.config['FILE_UPLOAD_FOLDER'] = 'static/uploads/shared_files'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt', 'mp3', 'mp4', 'zip'}

# Create upload folders if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['FILE_UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)  # Initialize the database
migrate = Migrate(app, db)  # Initialize Flask-Migrate
socketio = SocketIO(app)  # Initialize Socket.IO for real-time messaging
online_users = {}  # Dictionary to track users in each room
typing_users = {}  # Dictionary to track who is typing in each room

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_file_type(filename):
    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if extension in ['jpg', 'jpeg', 'png', 'gif']:
        return 'image'
    elif extension in ['mp4', 'webm', 'ogg']:
        return 'video'
    elif extension in ['mp3', 'wav']:
        return 'audio'
    else:
        return 'document'

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    profile_pic = db.Column(db.String(255), default='default.png')
    bio = db.Column(db.Text, default='')
    status_message = db.Column(db.String(100), default='')
    location = db.Column(db.String(100), default='')
    interests = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='online')  # online, offline, away, busy
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships for friends
    sent_friend_requests = db.relationship(
        'Friendship',
        foreign_keys='Friendship.user_id',
        backref='sender',
        lazy='dynamic'
    )
    received_friend_requests = db.relationship(
        'Friendship',
        foreign_keys='Friendship.friend_id',
        backref='receiver',
        lazy='dynamic'
    )
    
    # Method to get all friends
    def get_friends(self):
        sent = Friendship.query.filter_by(
            user_id=self.id, status='accepted'
        ).all()
        received = Friendship.query.filter_by(
            friend_id=self.id, status='accepted'
        ).all()
        
        friends = []
        for friendship in sent:
            friend = User.query.get(friendship.friend_id)
            if friend:
                friends.append(friend)
        for friendship in received:
            friend = User.query.get(friendship.user_id)
            if friend:
                friends.append(friend)
        
        return friends
    
    # Method to get friend requests
    def get_friend_requests(self):
        return Friendship.query.filter_by(
            friend_id=self.id, status='pending'
        ).all()

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, unique=True)
    topic = db.Column(db.String(100), default='General')  # Topic field
    description = db.Column(db.Text, default='')  # Description field
    created_by = db.Column(db.String(150), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Creator ID
    is_private = db.Column(db.Boolean, default=False)
    password = db.Column(db.String(150), nullable=True)  # For private rooms
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    creator = db.relationship('User', backref='created_rooms')
    
    # Get room admins
    def get_admins(self):
        return RoomMember.query.filter_by(room_id=self.id, role='admin').all()
    
    # Get room moderators
    def get_moderators(self):
        return RoomMember.query.filter_by(room_id=self.id, role='moderator').all()
    
    # Check if user is admin
    def is_admin(self, user_id):
        admin = RoomMember.query.filter_by(room_id=self.id, user_id=user_id, role='admin').first()
        return admin is not None
    
    # Check if user is moderator
    def is_moderator(self, user_id):
        mod = RoomMember.query.filter_by(room_id=self.id, user_id=user_id, role='moderator').first()
        return mod is not None or self.is_admin(user_id)

class RoomAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)

class RoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), default='member')  # 'admin', 'moderator', or 'member'
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    room = db.relationship('Room', backref='members')
    user = db.relationship('User', backref='room_memberships')
    
    # Unique constraint to ensure a user can only have one role per room
    __table_args__ = (db.UniqueConstraint('room_id', 'user_id', name='unique_room_member'),)

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure unique friendships
    __table_args__ = (db.UniqueConstraint('user_id', 'friend_id', name='unique_friendship'),)

class DirectMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    file_id = db.Column(db.Integer, db.ForeignKey('shared_file.id'), nullable=True)  # For file sharing
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')
    file = db.relationship('SharedFile', backref='direct_message')

class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)  # 'image', 'document', 'audio', 'video'
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=True)  # Null if direct message
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Not null for direct messages
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    file_size = db.Column(db.Integer)  # Size in bytes
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='uploaded_files')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_files')
    room = db.relationship('Room', backref='shared_files')

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=True)  # Can be null if it's a file-only message
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_id = db.Column(db.Integer, db.ForeignKey('shared_file.id'), nullable=True)
    
    # Relationships
    user = db.relationship('User', backref='chat_messages')
    room = db.relationship('Room', backref='messages')
    file = db.relationship('SharedFile', backref='message')

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    event_date = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with user (creator)
    creator = db.relationship('User', backref='created_events')
    
    # Get the number of attendees for this event
    def get_attendee_count(self):
        return EventAttendee.query.filter_by(event_id=self.id, status='going').count()
    
    # Check if a user is attending this event
    def is_user_attending(self, user_id):
        attendance = EventAttendee.query.filter_by(
            event_id=self.id, user_id=user_id
        ).first()
        return attendance.status if attendance else None

class EventAttendee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='going')  # going, maybe, not_going
    rsvp_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    event = db.relationship('Event', backref='attendees')
    user = db.relationship('User', backref='event_attendances')
    
    # Ensure a user can only have one RSVP per event
    __table_args__ = (db.UniqueConstraint('event_id', 'user_id', name='unique_event_attendance'),)

class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    icon = db.Column(db.String(50), default='fas fa-hashtag')  # FontAwesome icon class
    
    def __repr__(self):
        return f'<Topic {self.name}>'

class Update(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default='update')  # 'update', 'announcement', 'event'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='updates')
    likes = db.relationship('UpdateLike', backref='update', cascade='all, delete-orphan')
    comments = db.relationship('UpdateComment', backref='update', cascade='all, delete-orphan', order_by='UpdateComment.created_at')
    
    def get_like_count(self):
        return UpdateLike.query.filter_by(update_id=self.id).count()
    
    def is_liked_by(self, user_id):
        return UpdateLike.query.filter_by(update_id=self.id, user_id=user_id).first() is not None

class UpdateLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    update_id = db.Column(db.Integer, db.ForeignKey('update.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure a user can only like an update once
    __table_args__ = (db.UniqueConstraint('update_id', 'user_id', name='unique_update_like'),)

class UpdateComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    update_id = db.Column(db.Integer, db.ForeignKey('update.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='update_comments')

class RoomAnnouncement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    room = db.relationship('Room', backref='announcements')
    user = db.relationship('User', backref='room_announcements')
    
    def __repr__(self):
        return f'<RoomAnnouncement {self.id} for Room {self.room_id}>'

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Checks if username already exists
        if User.query.filter_by(username=username).first():
            message = "Username already exists!"
        else:
            # Adds the new user to the database
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            message = "Account successfully created! Please log in."

    return render_template('register.html', message=message)

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
       
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user'] = username  # Saves username in session
            session['user_id'] = user.id  # Save user ID in session
            
            # Update user status to online
            user.status = 'online'
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            return redirect(url_for('home'))
        else:
            message = "Invalid username or password!"

    return render_template('login.html', message=message)

@app.route('/', methods=['GET', 'POST'])
def home():
    if 'user' not in session:  # Redirects to login if user is not logged in
        return redirect(url_for('login'))

    message = None
    
    try:
        public_rooms = Room.query.filter_by(is_private=False).all()
        
        # Get private rooms the user has access to
        private_room_access = RoomAccess.query.filter_by(username=session['user']).all()
        private_room_ids = [access.room_id for access in private_room_access]
        private_rooms = Room.query.filter(Room.id.in_(private_room_ids)).all() if private_room_ids else []
    except Exception as e:
        # Fallback if columns don't exist yet
        public_rooms = Room.query.all()
        private_rooms = []
        print(f"Error querying rooms: {e}")
    
    # Get user info
    user = User.query.filter_by(username=session['user']).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Get friend count for display
    friends_count = len(user.get_friends())
    pending_requests_count = Friendship.query.filter_by(friend_id=user.id, status='pending').count()
    
    # Get topics for room creation
    topics = Topic.query.order_by(Topic.name).all()
    
    # Get announcements for slideshow
    announcements = Update.query.filter_by(type='announcement').order_by(Update.created_at.desc()).limit(5).all()
    
    # Get recent updates for dashboard
    recent_updates = Update.query.filter_by(type='update').order_by(Update.created_at.desc()).limit(3).all()
    
    # Add like counts to updates and announcements
    for update in announcements + recent_updates:
        update.like_count = update.get_like_count()
        update.is_liked = update.is_liked_by(user.id)
    
    if request.method == 'POST':
        if 'room_code' in request.form:
            # User is joining an existing room
            room_code = request.form['room_code']
            room = Room.query.filter_by(name=room_code).first()
            
            if not room:
                message = "Room doesn't exist!"
            elif hasattr(room, 'is_private') and room.is_private:
                # Check if user has access or needs password
                access = RoomAccess.query.filter_by(room_id=room.id, username=session['user']).first()
                if access:
                    return redirect(url_for('chat', room_code=room_code))
                elif 'room_password' in request.form:
                    # Verify room password
                    if check_password_hash(room.password, request.form['room_password']):
                        # Grant access
                        new_access = RoomAccess(room_id=room.id, username=session['user'])
                        db.session.add(new_access)
                        db.session.commit()
                        return redirect(url_for('chat', room_code=room_code))
                    else:
                        message = "Incorrect password for private room!"
                else:
                    # Show password prompt
                    return render_template('private_room_access.html', room_code=room_code)
            else:
                return redirect(url_for('chat', room_code=room_code))
                
        elif 'room_name' in request.form:
            # User is creating a new room
            room_name = request.form['room_name']
            is_private = 'is_private' in request.form
            room_password = request.form.get('room_password', '')
            room_topic = request.form.get('topic', 'General')
            room_description = request.form.get('description', '')
            
            # Check if room name already exists
            existing_room = Room.query.filter_by(name=room_name).first()
            if existing_room:
                message = "Room already exists! Try joining it or use a different name."
            else:
                # Create new room
                new_room = Room(
                    name=room_name, 
                    created_by=session['user'],
                    created_by_id=user.id,
                    is_private=is_private,
                    topic=room_topic,
                    description=room_description
                )
                
                # Set password for private rooms
                if is_private and room_password:
                    new_room.password = generate_password_hash(room_password, method='pbkdf2:sha256')
                
                db.session.add(new_room)
                db.session.commit()
                
                # Add creator as admin
                admin_member = RoomMember(
                    room_id=new_room.id,
                    user_id=user.id,
                    username=user.username,
                    role='admin'
                )
                db.session.add(admin_member)
                
                # For private rooms, grant access to creator
                if is_private:
                    access = RoomAccess(room_id=new_room.id, username=session['user'])
                    db.session.add(access)
                
                db.session.commit()
                
                return redirect(url_for('chat', room_code=room_name))

    return render_template(
        'index.html', 
        username=session['user'], 
        public_rooms=public_rooms, 
        private_rooms=private_rooms, 
        message=message,
        user=user,
        friends_count=friends_count,
        pending_requests_count=pending_requests_count,
        topics=topics,
        announcements=announcements,
        recent_updates=recent_updates
    )

@app.route('/chat/<room_code>')
def chat(room_code):
    if 'user' not in session:  
        return redirect(url_for('login'))
    
    # Check if room exists
    room = Room.query.filter_by(name=room_code).first()
    if not room:
        flash("Room doesn't exist!")
        return redirect(url_for('home'))
    
    # Check access for private rooms
    if hasattr(room, 'is_private') and room.is_private:
        access = RoomAccess.query.filter_by(room_id=room.id, username=session['user']).first()
        if not access:
            flash("You don't have access to this private room!")
            return redirect(url_for('home'))
    
    # Get user info for displaying profile
    user = User.query.filter_by(username=session['user']).first()
    if not user:
        return redirect(url_for('logout'))
    
    # Check if user is admin or moderator
    is_admin = room.is_admin(user.id)
    is_moderator = room.is_moderator(user.id)
    
    # Get recent messages
    recent_messages = ChatMessage.query.filter_by(room_id=room.id).order_by(ChatMessage.timestamp.desc()).limit(50).all()
    recent_messages.reverse()  # Show oldest first
    
    # Get room announcements
    room_announcements = RoomAnnouncement.query.filter_by(room_id=room.id).order_by(RoomAnnouncement.created_at.desc()).all()
    
    return render_template('chat.html', 
                          room_code=room_code, 
                          username=session['user'], 
                          user=user, 
                          room=room,
                          is_admin=is_admin,
                          is_moderator=is_moderator,
                          recent_messages=recent_messages,
                          room_announcements=room_announcements)

@app.route('/manage_topics', methods=['GET', 'POST'])
def manage_topics():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            topic_name = request.form.get('topic_name')
            description = request.form.get('description')
            icon = request.form.get('icon', 'fas fa-hashtag')
            
            # Check if topic already exists
            existing = Topic.query.filter_by(name=topic_name).first()
            if existing:
                flash('Topic already exists')
            else:
                new_topic = Topic(name=topic_name, description=description, icon=icon)
                db.session.add(new_topic)
                db.session.commit()
                flash('Topic added successfully')
        
        elif action == 'delete':
            topic_id = request.form.get('topic_id')
            topic = Topic.query.get_or_404(topic_id)
            
            # Check if topic is in use
            rooms_using_topic = Room.query.filter_by(topic=topic.name).count()
            if rooms_using_topic > 0:
                flash(f'Cannot delete topic - it is used by {rooms_using_topic} rooms')
            else:
                db.session.delete(topic)
                db.session.commit()
                flash('Topic deleted successfully')
    
    # Get all topics
    topics = Topic.query.order_by(Topic.name).all()
    return render_template('manage_topics.html', topics=topics)

@app.route('/browse_rooms')
def browse_rooms():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get filter parameters
    topic = request.args.get('topic', 'all')
    search = request.args.get('search', '')
    
    # Base query - public rooms
    query = Room.query.filter_by(is_private=False)
    
    # Apply topic filter if not 'all'
    if topic != 'all':
        query = query.filter_by(topic=topic)
    
    # Apply search filter if provided
    if search:
        query = query.filter(Room.name.like(f'%{search}%'))
    
    # Get rooms
    rooms = query.order_by(Room.created_at.desc()).all()
    
    # Get all topics for filter dropdown
    topics = Topic.query.order_by(Topic.name).all()
    
    return render_template('browse_rooms.html', rooms=rooms, topics=topics, 
                          current_topic=topic, search=search)

@app.route('/room/<int:room_id>')
def room_by_id(room_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    room = Room.query.get_or_404(room_id)
    
    # Redirect to the chat route
    return redirect(url_for('chat', room_code=room.name))

@app.route('/room/<int:room_id>/manage', methods=['GET', 'POST'])
def manage_room(room_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    room = Room.query.get_or_404(room_id)
    
    # Check if user is admin
    if not room.is_admin(current_user.id) and room.created_by_id != current_user.id:
        flash("You don't have permission to manage this room")
        return redirect(url_for('chat', room_code=room.name))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_info':
            # Update room information
            room.description = request.form.get('description', '')
            room.topic = request.form.get('topic')
            db.session.commit()
            flash('Room information updated')
        
        elif action == 'manage_member':
            user_id = request.form.get('user_id', type=int)
            role = request.form.get('role')
            
            # Check if user exists
            user = User.query.get(user_id)
            if not user:
                flash('User not found')
            else:
                # Check if user is already a member
                member = RoomMember.query.filter_by(room_id=room.id, user_id=user_id).first()
                
                if role == 'remove':
                    # Remove user from room
                    if member:
                        db.session.delete(member)
                        db.session.commit()
                        flash(f'Removed {user.username} from the room')
                else:
                    # Add or update role
                    if member:
                        member.role = role
                    else:
                        new_member = RoomMember(
                            room_id=room.id,
                            user_id=user_id,
                            username=user.username,
                            role=role
                        )
                        db.session.add(new_member)
                    
                    db.session.commit()
                    flash(f'Updated {user.username} to {role}')
    
    # Get room members with roles
    members = RoomMember.query.filter_by(room_id=room.id).all()
    
    # Get all topics
    topics = Topic.query.order_by(Topic.name).all()
    
    return render_template('manage_room.html', room=room, members=members, topics=topics)

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    # Get room information
    room_id = request.form.get('room_id', type=int)
    receiver_id = request.form.get('receiver_id', type=int)
    
    # Generate unique filename
    original_filename = secure_filename(file.filename)
    file_extension = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
    unique_filename = f"{uuid.uuid4().hex}.{file_extension}"
    
    # Save file
    file_path = os.path.join(app.config['FILE_UPLOAD_FOLDER'], unique_filename)
    file.save(file_path)
    
    # Get file size
    file_size = os.path.getsize(file_path)
    
    # Determine file type
    file_type = get_file_type(original_filename)
    
    # Create SharedFile record
    new_file = SharedFile(
        filename=unique_filename,
        original_filename=original_filename,
        file_type=file_type,
        room_id=room_id,
        sender_id=current_user.id,
        receiver_id=receiver_id,
        file_size=file_size
    )
    
    db.session.add(new_file)
    db.session.commit()
    
    # Return file info
    return jsonify({
        'file_id': new_file.id,
        'filename': unique_filename,
        'original_filename': original_filename,
        'file_type': file_type,
        'file_size': file_size
    })

@app.route('/files/<filename>')
def get_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get file info from database
    file_record = SharedFile.query.filter_by(filename=filename).first_or_404()
    
    # Get current user
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    # Check permissions
    has_access = False
    
    if file_record.room_id:
        # Check if user has access to the room
        room = Room.query.get(file_record.room_id)
        if room and not room.is_private:
            # Public room - anyone can access
            has_access = True
        else:
            # Private room - check membership
            access = RoomAccess.query.filter_by(room_id=room.id, username=session['user']).first()
            has_access = access is not None
    else:
        # Direct message file - check if user is sender or recipient
        has_access = (file_record.sender_id == current_user.id or 
                     file_record.receiver_id == current_user.id)
    
    if not has_access:
        flash("You don't have permission to access this file")
        return redirect(url_for('home'))
    
    # Serve the file
    file_path = os.path.join(app.config['FILE_UPLOAD_FOLDER'], filename)
    
    # Try to guess content type
    content_type = mimetypes.guess_type(file_record.original_filename)[0]
    
    # Set content disposition based on file type
    if file_record.file_type == 'image':
        # For images, allow inline display
        return send_file(file_path, mimetype=content_type)
    else:
        # For other files, force download
        return send_file(file_path, 
                        mimetype=content_type,
                        as_attachment=True, 
                        download_name=file_record.original_filename)

@app.route('/private_room/<room_code>', methods=['GET', 'POST'])
def private_room_access(room_code):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        return redirect(url_for('home'))
    
    return render_template('private_room_access.html', room_code=room_code)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['user']).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
        
    message = None
    
    if request.method == 'POST':
        # Update user profile
        user.bio = request.form.get('bio', '')
        user.status_message = request.form.get('status_message', '')
        user.location = request.form.get('location', '')
        user.interests = request.form.get('interests', '')
        
        # Handle profile picture upload with cropping
        cropped_data = request.form.get('cropped_data')
        if cropped_data and cropped_data.startswith('data:image'):
            try:
                # Extract the base64 encoded image
                format, imgstr = cropped_data.split(';base64,')
                ext = format.split('/')[-1]
                
                # Generate unique filename
                filename = f"{uuid.uuid4().hex}.{ext}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Save the decoded image
                with open(file_path, "wb") as f:
                    f.write(base64.b64decode(imgstr))
                
                # Update database
                user.profile_pic = filename
            except Exception as e:
                print(f"Error saving cropped image: {e}")
        elif 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename and allowed_file(file.filename):
                # Generate unique filename
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                # Save file
                file.save(file_path)
                
                # Update database
                user.profile_pic = unique_filename
        
        db.session.commit()
        message = "Profile updated successfully!"
    
    return render_template('profile.html', user=user, message=message)

@app.route('/logout')
def logout():
    # Update user status to offline
    if 'user' in session:
        user = User.query.filter_by(username=session['user']).first()
        if user:
            user.status = 'offline'
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            # Broadcast status update
            socketio.emit('status_update', {
                'user_id': user.id,
                'username': user.username,
                'status': 'offline'
            })
    
    session.pop('user', None)
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/users')
def users():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    # Get search query if it exists
    search_query = request.args.get('search', '')
    
    # Get all users except the current user, filtered by search if provided
    if search_query:
        all_users = User.query.filter(
            User.id != current_user.id,
            User.username.ilike(f'%{search_query}%')  # Case-insensitive search
        ).all()
    else:
        all_users = User.query.filter(User.id != current_user.id).all()
    
    # Get current user's friends
    friends = current_user.get_friends()
    friend_ids = [friend.id for friend in friends]
    
    # Get pending requests
    sent_requests = Friendship.query.filter_by(
        user_id=current_user.id, status='pending'
    ).all()
    sent_request_ids = [fr.friend_id for fr in sent_requests]
    
    received_requests = Friendship.query.filter_by(
        friend_id=current_user.id, status='pending'
    ).all()
    received_request_ids = [fr.user_id for fr in received_requests]
    
    return render_template(
        'users.html',
        users=all_users,
        current_user=current_user,
        friend_ids=friend_ids,
        sent_request_ids=sent_request_ids,
        received_request_ids=received_request_ids,
        search_query=search_query
    )

@app.route('/add_friend/<int:user_id>')
def add_friend(user_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    # Check if friend request already exists
    existing_request = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == user_id)) |
        ((Friendship.user_id == user_id) & (Friendship.friend_id == current_user.id))
    ).first()
    
    if existing_request:
        flash('Friend request already exists or you are already friends')
    else:
        friendship = Friendship(user_id=current_user.id, friend_id=user_id)
        db.session.add(friendship)
        db.session.commit()
        flash('Friend request sent!')
    
    return redirect(url_for('users'))

@app.route('/accept_friend/<int:user_id>')
def accept_friend(user_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    # Find the friendship request
    friendship = Friendship.query.filter_by(
        user_id=user_id, friend_id=current_user.id, status='pending'
    ).first()
    
    if friendship:
        friendship.status = 'accepted'
        db.session.commit()
        flash('Friend request accepted!')
    else:
        flash('Friend request not found')
    
    return redirect(url_for('users'))

@app.route('/reject_friend/<int:user_id>')
def reject_friend(user_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    # Find the friendship request
    friendship = Friendship.query.filter_by(
        user_id=user_id, friend_id=current_user.id, status='pending'
    ).first()
    
    if friendship:
        db.session.delete(friendship)
        db.session.commit()
        flash('Friend request rejected')
    else:
        flash('Friend request not found')
    
    return redirect(url_for('users'))

@app.route('/remove_friend/<int:user_id>')
def remove_friend(user_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    # Find the friendship
    friendship = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == user_id)) |
        ((Friendship.user_id == user_id) & (Friendship.friend_id == current_user.id)),
        Friendship.status == 'accepted'
    ).first()
    
    if friendship:
        db.session.delete(friendship)
        db.session.commit()
        flash('Friend removed')
    else:
        flash('Friendship not found')
    
    return redirect(url_for('users'))

@app.route('/update_status/<status>')
def update_status(status):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if status not in ['online', 'offline', 'away', 'busy']:
        flash('Invalid status')
        return redirect(url_for('home'))
    
    user = User.query.filter_by(username=session['user']).first()
    if user:
        user.status = status
        user.last_seen = datetime.utcnow()
        db.session.commit()
        
        # Emit status change to all connected clients
        socketio.emit('status_update', {
            'user_id': user.id,
            'username': user.username,
            'status': status
        })
    
    return redirect(request.referrer or url_for('home'))

@app.route('/messages')
def messages():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    # Get all friends
    friends = current_user.get_friends()
    
    return render_template('messages.html', friends=friends, current_user=current_user)

@app.route('/direct_chat/<int:user_id>')
def direct_chat(user_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    friend = User.query.get_or_404(user_id)
    
    # Check if they are friends
    friends = current_user.get_friends()
    is_friend = False
    for f in friends:
        if f.id == friend.id:
            is_friend = True
            break
            
    if not is_friend:
        flash("You can only message your friends")
        return redirect(url_for('messages'))
    
    # Mark messages as read
    unread_messages = DirectMessage.query.filter_by(
        sender_id=friend.id, receiver_id=current_user.id, is_read=False
    ).all()
    
    for msg in unread_messages:
        msg.is_read = True
    db.session.commit()
    
    # Get message history
    sent_messages = DirectMessage.query.filter_by(
        sender_id=current_user.id, receiver_id=friend.id
    ).all()
    received_messages = DirectMessage.query.filter_by(
        sender_id=friend.id, receiver_id=current_user.id
    ).all()
    
    messages = sorted(
        sent_messages + received_messages,
        key=lambda x: x.timestamp
    )
    
    return render_template('direct_chat.html', friend=friend, messages=messages, current_user=current_user)

@app.route('/events')
def events():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    # Get all upcoming events (where event date is in the future)
    upcoming_events = Event.query.filter(Event.event_date > datetime.utcnow()).order_by(Event.event_date).all()
    
    # Get events created by the current user
    user_events = Event.query.filter_by(created_by=current_user.id).all()
    
    # Get events the user is attending
    attending_events_ids = [attendance.event_id for attendance in 
                           EventAttendee.query.filter_by(user_id=current_user.id, status='going').all()]
    attending_events = Event.query.filter(Event.id.in_(attending_events_ids)).all() if attending_events_ids else []
    
    return render_template('events.html', 
                           upcoming_events=upcoming_events,
                           user_events=user_events,
                           attending_events=attending_events,
                           current_user=current_user)

@app.route('/events/create', methods=['GET', 'POST'])
def create_event():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        
        # Parse event date and time
        event_date_str = request.form['event_date']
        event_time_str = request.form['event_time']
        
        try:
            # Combine date and time
            event_datetime_str = f"{event_date_str} {event_time_str}"
            event_datetime = datetime.strptime(event_datetime_str, '%Y-%m-%d %H:%M')
            
            # Create the event
            new_event = Event(
                title=title,
                description=description,
                location=location,
                event_date=event_datetime,
                created_by=current_user.id
            )
            
            db.session.add(new_event)
            db.session.commit()
            
            # Automatically make creator attend the event
            attendance = EventAttendee(
                event_id=new_event.id,
                user_id=current_user.id,
                status='going'
            )
            
            db.session.add(attendance)
            db.session.commit()
            
            flash('Event created successfully!')
            return redirect(url_for('events'))
            
        except Exception as e:
            flash(f'Error creating event: {str(e)}')
    
    return render_template('create_event.html', current_user=current_user)

@app.route('/event/<int:event_id>')
def view_event(event_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    event = Event.query.get_or_404(event_id)
    
    # Get attendees for this event
    attendees = EventAttendee.query.filter_by(event_id=event_id, status='going').all()
    attendee_users = [User.query.get(attendee.user_id) for attendee in attendees]
    
    # Check if current user is attending
    user_status = event.is_user_attending(current_user.id)
    
    return render_template('view_event.html', 
                           event=event, 
                           attendees=attendee_users, 
                           current_user=current_user,
                           user_status=user_status)

@app.route('/event/<int:event_id>/rsvp/<status>')
def rsvp_event(event_id, status):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if status not in ['going', 'maybe', 'not_going']:
        flash('Invalid RSVP status')
        return redirect(url_for('view_event', event_id=event_id))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    event = Event.query.get_or_404(event_id)
    
    # Check if user already has an RSVP
    existing_rsvp = EventAttendee.query.filter_by(
        event_id=event_id, user_id=current_user.id
    ).first()
    
    if existing_rsvp:
        existing_rsvp.status = status
        existing_rsvp.rsvp_at = datetime.utcnow()
    else:
        new_rsvp = EventAttendee(
            event_id=event_id,
            user_id=current_user.id,
            status=status
        )
        db.session.add(new_rsvp)
    
    db.session.commit()
    
    status_messages = {
        'going': 'You are now attending this event!',
        'maybe': 'You have marked that you might attend this event.',
        'not_going': 'You have declined to attend this event.'
    }
    
    flash(status_messages[status])
    return redirect(url_for('view_event', event_id=event_id))

@app.route('/event/<int:event_id>/delete', methods=['POST'])
def delete_event(event_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    event = Event.query.get_or_404(event_id)
    
    # Only the creator can delete the event
    if event.created_by != current_user.id:
        flash('You do not have permission to delete this event')
        return redirect(url_for('view_event', event_id=event_id))
    
    # Delete all attendees
    EventAttendee.query.filter_by(event_id=event_id).delete()
    
    # Delete the event
    db.session.delete(event)
    db.session.commit()
    
    flash('Event has been deleted')
    return redirect(url_for('events'))

@app.route('/newsfeed')
def newsfeed():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    # Get updates ordered by creation time
    updates = Update.query.order_by(Update.created_at.desc()).all()
    
    # Add like counts to updates
    for update in updates:
        update.like_count = update.get_like_count()
        update.is_liked = update.is_liked_by(current_user.id)
    
    # Get upcoming events
    upcoming_events = Event.query.filter(Event.event_date > datetime.utcnow()).order_by(Event.event_date).limit(3).all()
    
    # Get active rooms (rooms with recent messages)
    active_rooms = []
    rooms = Room.query.filter_by(is_private=False).all()
    for room in rooms:
        # Count messages in the last 24 hours
        recent_messages = ChatMessage.query.filter_by(room_id=room.id).filter(
            ChatMessage.timestamp > datetime.utcnow() - timedelta(hours=24)
        ).count()
        
        if recent_messages > 0:
            active_rooms.append({
                'id': room.id,
                'name': room.name,
                'topic': room.topic,
                'recent_messages': recent_messages
            })
    
    # Sort active rooms by recent message count, show most active first
    active_rooms.sort(key=lambda x: x['recent_messages'], reverse=True)
    active_rooms = active_rooms[:5]  # Limit to 5 most active rooms
    
    return render_template('newsfeed.html', 
                          updates=updates, 
                          upcoming_events=upcoming_events,
                          active_rooms=active_rooms,
                          current_user=current_user)

@app.route('/newsfeed/create_announcement', methods=['GET', 'POST'])
def create_announcement():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return redirect(url_for('logout'))
    
    # Get rooms where user is admin or moderator (for room announcement targeting)
    admin_rooms = []
    mod_rooms = []
    
    room_memberships = RoomMember.query.filter_by(user_id=current_user.id).all()
    for membership in room_memberships:
        room = Room.query.get(membership.room_id)
        if room:
            if membership.role == 'admin':
                admin_rooms.append(room)
            elif membership.role == 'moderator':
                mod_rooms.append(room)
    
    # Check if we're pre-selecting a room (from room page)
    pre_selected_room_id = request.args.get('room_id')
    
    if request.method == 'POST':
        content = request.form.get('content')
        target = request.form.get('target', 'community')  # 'community' or 'room'
        
        if not content:
            flash('Announcement content cannot be empty')
            return redirect(url_for('create_announcement'))
        
        # Create community announcement
        if target == 'community':
            new_update = Update(
                user_id=current_user.id,
                content=content,
                type='announcement'
            )
            
            db.session.add(new_update)
            db.session.commit()
            flash('Community announcement has been posted!')
            return redirect(url_for('newsfeed'))
        
        # Create room-specific announcement
        elif target == 'room':
            room_ids = request.form.getlist('room_ids')
            
            if not room_ids:
                flash('Please select at least one room for the announcement')
                return redirect(url_for('create_announcement'))
            
            for room_id in room_ids:
                room = Room.query.get(int(room_id))
                
                # Check if user has permission to post announcements in this room
                is_admin = room.is_admin(current_user.id)
                is_moderator = room.is_moderator(current_user.id)
                
                if room and (is_admin or is_moderator):
                    room_announcement = RoomAnnouncement(
                        room_id=room.id,
                        user_id=current_user.id,
                        content=content
                    )
                    db.session.add(room_announcement)
            
            db.session.commit()
            flash('Room announcement(s) have been posted!')
            return redirect(url_for('newsfeed'))
    
    return render_template(
        'create_announcement.html',
        admin_rooms=admin_rooms,
        mod_rooms=mod_rooms,
        current_user=current_user,
        pre_selected_room_id=pre_selected_room_id
    )

@app.route('/chat/<room_code>/announcements')
def room_announcements(room_code):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    room = Room.query.filter_by(name=room_code).first_or_404()
    
    # Get room announcements, newest first
    announcements = RoomAnnouncement.query.filter_by(room_id=room.id).order_by(RoomAnnouncement.created_at.desc()).all()
    
    return render_template(
        'room_announcements.html',
        room=room,
        announcements=announcements
    )

@app.route('/newsfeed/post', methods=['POST'])
def post_update():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    content = request.form.get('content')
    update_type = request.form.get('update_type', 'update')
    
    if not content:
        flash('Update content cannot be empty')
        return redirect(url_for('newsfeed'))
    
    # Create new update
    new_update = Update(
        user_id=current_user.id,
        content=content,
        type=update_type
    )
    
    db.session.add(new_update)
    db.session.commit()
    
    flash('Your update has been posted!')
    return redirect(url_for('newsfeed'))

@app.route('/newsfeed/like/<int:update_id>', methods=['POST'])
def like_update(update_id):
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    update = Update.query.get_or_404(update_id)
    
    # Check if user already liked this update
    existing_like = UpdateLike.query.filter_by(
        update_id=update_id, user_id=current_user.id
    ).first()
    
    if existing_like:
        # Unlike
        db.session.delete(existing_like)
        db.session.commit()
        liked = False
    else:
        # Like
        new_like = UpdateLike(
            update_id=update_id,
            user_id=current_user.id
        )
        db.session.add(new_like)
        db.session.commit()
        liked = True
    
    # Get updated like count
    likes = update.get_like_count()
    
    return jsonify({
        'likes': likes,
        'liked': liked
    })
    
@app.route('/newsfeed/comment/<int:update_id>', methods=['POST'])
def comment_update(update_id):
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    comment_text = data.get('comment')
    
    if not comment_text:
        return jsonify({'error': 'Comment cannot be empty'}), 400
    
    update = Update.query.get_or_404(update_id)
    
    # Add comment
    new_comment = UpdateComment(
        update_id=update_id,
        user_id=current_user.id,
        text=comment_text
    )
    
    db.session.add(new_comment)
    db.session.commit()
    
    return jsonify({
        'id': new_comment.id,
        'username': current_user.username,
        'profile_pic': current_user.profile_pic,
        'comment': comment_text,
        'created_at': new_comment.created_at.strftime('%b %d, %Y at %I:%M %p')
    })

@app.route('/newsfeed/update/<int:update_id>', methods=['POST'])
def edit_update(update_id):
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    update = Update.query.get_or_404(update_id)
    
    # Check if user is the author
    if update.user_id != current_user.id:
        return jsonify({'error': 'Not authorized to edit this update'}), 403
    
    data = request.get_json()
    new_content = data.get('content')
    
    if not new_content:
        return jsonify({'error': 'Content cannot be empty'}), 400
    
    update.content = new_content
    update.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/newsfeed/delete/<int:update_id>', methods=['POST'])
def delete_update(update_id):
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    update = Update.query.get_or_404(update_id)
    
    # Check if user is the author
    if update.user_id != current_user.id:
        return jsonify({'error': 'Not authorized to delete this update'}), 403
    
    db.session.delete(update)
    db.session.commit()
    
    return jsonify({'success': True})

# Socket.IO Event Handlers
@socketio.on('join')
def handle_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
    
    # Add user to online users for this room
    if room not in online_users:
        online_users[room] = []
    if username not in online_users[room]:
        online_users[room].append(username)
    
    # Initialize typing users for this room if needed
    if room not in typing_users:
        typing_users[room] = []
    
    # Get user profile info
    user = User.query.filter_by(username=username).first()
    user_data = {
        'username': username,
        'profile_pic': user.profile_pic if user and hasattr(user, 'profile_pic') else 'default.png',
        'status_message': user.status_message if user and hasattr(user, 'status_message') else ''
    }
    
    # Get room info
    room_obj = Room.query.filter_by(name=room).first()
    room_id = room_obj.id if room_obj else None
    
    if room_id:
        # Check if user is admin or moderator
        is_admin = False
        is_moderator = False
        
        if user:
            is_admin = room_obj.is_admin(user.id)
            is_moderator = room_obj.is_moderator(user.id)
        
        user_data['is_admin'] = is_admin
        user_data['is_moderator'] = is_moderator
    
    # Notify room about new user
    send(f'{username} has joined the room!', to=room)
    
    # Send updated user list to everyone in the room
    user_profiles = []
    user_roles = []
    
    for u in online_users[room]:
        user_obj = User.query.filter_by(username=u).first()
        if user_obj:
            # Get profile pic
            profile_pic = user_obj.profile_pic if hasattr(user_obj, 'profile_pic') else 'default.png'
            user_profiles.append(profile_pic)
            
            # Get role if room exists
            role = 'member'
            if room_id:
                member = RoomMember.query.filter_by(room_id=room_id, user_id=user_obj.id).first()
                if member:
                    role = member.role
            
            user_roles.append(role)
        else:
            user_profiles.append('default.png')
            user_roles.append('member')
            
    socketio.emit('user_list', {
        'users': online_users[room],
        'user_profiles': user_profiles,
        'user_roles': user_roles
    }, to=room)

@socketio.on('join_direct')
def handle_join_direct(data):
    user_id = data.get('user_id')
    friend_id = data.get('friend_id')
    
    if user_id and friend_id:
        # Create a unique room name for the two users (sorted for consistency)
        room = f"direct_{min(user_id, friend_id)}_{max(user_id, friend_id)}"
        join_room(room)
        print(f"User {user_id} joined direct chat room {room}")

@socketio.on('message')
def handle_message(data):
    room = data['room']
    username = data['username']
    message_text = data.get('message', '')
    file_id = data.get('file_id')
   
    # Format timestamp in 12-hour format with AM/PM
    current_time = datetime.utcnow()
    timestamp = current_time.strftime('%I:%M %p')

    # Get user info
    user = User.query.filter_by(username=username).first()
    if not user:
        return
    
    profile_pic = user.profile_pic if hasattr(user, 'profile_pic') else 'default.png'
    
    # Get room ID
    room_obj = Room.query.filter_by(name=room).first()
    if not room_obj:
        return
    
    # Create message in database
    chat_message = ChatMessage(
        room_id=room_obj.id,
        user_id=user.id,
        username=username,
        message=message_text,
        timestamp=current_time,
        file_id=file_id
    )
    
    db.session.add(chat_message)
    db.session.commit()
    
    # Get file information if present
    file_data = None
    if file_id:
        file = SharedFile.query.get(file_id)
        if file:
            file_data = {
                'id': file.id,
                'filename': file.filename,
                'original_filename': file.original_filename,
                'file_type': file.file_type,
                'file_size': file.file_size
            }
    
    # Check if user is admin or moderator
    is_admin = room_obj.is_admin(user.id)
    is_moderator = room_obj.is_moderator(user.id)
    
    # Create message data to send
    message_data = {
        'id': chat_message.id,
        'username': username,
        'message': message_text,
        'timestamp': timestamp,
        'profile_pic': profile_pic,
        'file': file_data,
        'is_admin': is_admin,
        'is_moderator': is_moderator
    }

    # Remove user from typing list when they send a message
    if room in typing_users and username in typing_users[room]:
        typing_users[room].remove(username)
        socketio.emit('typing', {'users': typing_users[room]}, to=room)

    # Use socketio.emit instead of send for more reliable delivery
    socketio.emit('message', message_data, to=room)

@socketio.on('direct_message')
def handle_direct_message(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    message_text = data.get('message')
    file_id = data.get('file_id')
    
    if sender_id and receiver_id and (message_text or file_id):
        # Save to database
        dm = DirectMessage(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message=message_text if message_text else '',
            file_id=file_id
        )
        db.session.add(dm)
        db.session.commit()
        
        # Get sender info
        sender = User.query.get(sender_id)
        
        # Create unique room name
        room = f"direct_{min(sender_id, receiver_id)}_{max(sender_id, receiver_id)}"
        
        # Format timestamp
        timestamp = dm.timestamp.strftime('%I:%M %p')
        
        # Get file information if present
        file_data = None
        if file_id:
            file = SharedFile.query.get(file_id)
            if file:
                file_data = {
                    'id': file.id,
                    'filename': file.filename,
                    'original_filename': file.original_filename,
                    'file_type': file.file_type,
                    'file_size': file.file_size
                }
        
        # Send message to room
        socketio.emit('direct_message', {
            'id': dm.id,
            'sender_id': sender_id,
            'sender_username': sender.username,
            'sender_profile_pic': sender.profile_pic,
            'message': message_text,
            'timestamp': timestamp,
            'is_read': False,
            'file': file_data
        }, to=room)

@socketio.on('room_announcement')
def handle_room_announcement(data):
    if 'user' not in session:
        return
    
    room_id = data.get('room_id')
    content = data.get('content')
    
    if not room_id or not content:
        return
    
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        return
    
    # Check permissions
    room = Room.query.get(room_id)
    if not room:
        return
    
    is_admin = room.is_admin(current_user.id)
    is_moderator = room.is_moderator(current_user.id)
    
    if not (is_admin or is_moderator):
        return  # Not authorized
    
    # Create announcement
    announcement = RoomAnnouncement(
        room_id=room_id,
        user_id=current_user.id,
        content=content
    )
    
    db.session.add(announcement)
    db.session.commit()
    
    # Broadcast to room
    socketio.emit('new_announcement', {
        'id': announcement.id,
        'content': content,
        'username': current_user.username,
        'profile_pic': current_user.profile_pic,
        'timestamp': announcement.created_at.strftime('%b %d, %Y at %I:%M %p')
    }, to=room.name)
    
    return True

@socketio.on('typing')
def handle_typing(data):
    username = data['username']
    room = data['room']
    is_typing = data['typing']
    
    # Initialize typing_users for this room if it doesn't exist
    if room not in typing_users:
        typing_users[room] = []
    
    # Add or remove the user from typing list
    if is_typing and username not in typing_users[room]:
        typing_users[room].append(username)
    elif not is_typing and username in typing_users[room]:
        typing_users[room].remove(username)
    
    # Broadcast updated typing users list
    socketio.emit('typing', {'users': typing_users[room]}, to=room)

@socketio.on('leave')
def handle_leave(data):
    try:
        username = data['username']
        room = data['room']
        leave_room(room)
        
        # Remove user from online users
        if room in online_users and username in online_users[room]:
            online_users[room].remove(username)
        
        # Remove user from typing users
        if room in typing_users and username in typing_users[room]:
            typing_users[room].remove(username)
            socketio.emit('typing', {'users': typing_users[room]}, to=room)
        
        # Notify room that user left
        socketio.emit('user_left', {'message': f'{username} has left the room.'}, to=room)
        
        # Send updated user list to everyone in the room
        user_profiles = []
        user_roles = []
        
        # Get room info
        room_obj = Room.query.filter_by(name=room).first()
        room_id = room_obj.id if room_obj else None
        
        if room in online_users and online_users[room]:
            for u in online_users[room]:
                user_obj = User.query.filter_by(username=u).first()
                if user_obj:
                    # Get profile pic
                    profile_pic = user_obj.profile_pic if hasattr(user_obj, 'profile_pic') else 'default.png'
                    user_profiles.append(profile_pic)
                    
                    # Get role if room exists
                    role = 'member'
                    if room_id:
                        member = RoomMember.query.filter_by(room_id=room_id, user_id=user_obj.id).first()
                        if member:
                            role = member.role
                    
                    user_roles.append(role)
                else:
                    user_profiles.append('default.png')
                    user_roles.append('member')
        
        socketio.emit('user_list', {
            'users': online_users[room] if room in online_users else [],
            'user_profiles': user_profiles,
            'user_roles': user_roles
        }, to=room)
        
        # Return success to client
        return True
    except Exception as e:
        print(f"Error in leave room: {e}")
        return False
    
@socketio.on('edit_message')
def handle_edit_message(data):
    if 'user' not in session:
        return
    
    room = data.get('room')
    message_id = data.get('message_id')
    new_text = data.get('new_text')
    
    if not all([room, message_id, new_text]):
        return
    
    # Get message from database
    message = ChatMessage.query.get(message_id)
    if not message:
        return
    
    # Check if user is authorized to edit
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user or message.user_id != current_user.id:
        return
    
    # Update message
    message.message = new_text
    db.session.commit()
    
    # Broadcast to room
    socketio.emit('message_edited', {
        'message_id': message_id,
        'new_text': new_text
    }, to=room)

@socketio.on('delete_message')
def handle_delete_message(data):
    if 'user' not in session:
        return
    
    room = data.get('room')
    message_id = data.get('message_id')
    
    if not all([room, message_id]):
        return
    
    # Get message from database
    message = ChatMessage.query.get(message_id)
    if not message:
        return
    
    # Check if user is authorized to delete
    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user or message.user_id != current_user.id:
        return
    
    # Delete message
    db.session.delete(message)
    db.session.commit()
    
    # Broadcast to room
    socketio.emit('message_deleted', {
        'message_id': message_id
    }, to=room)

@socketio.on('connect')
def handle_connect():
    if 'user' in session:
        username = session['user']
        user = User.query.filter_by(username=username).first()
        
        if user:
            # Update user status to online
            user.status = 'online'
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            # Broadcast status update
            socketio.emit('status_update', {
                'user_id': user.id,
                'username': user.username,
                'status': 'online'
            })

@socketio.on('disconnect')
def handle_disconnect():
    if 'user' in session:
        username = session['user']
        user = User.query.filter_by(username=username).first()
        
        if user:
            # Update user status to offline
            user.status = 'offline'
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            # Broadcast status update
            socketio.emit('status_update', {
                'user_id': user.id,
                'username': user.username,
                'status': 'offline'
            })
            
            # Remove from all rooms
            for room in list(online_users.keys()):
                if username in online_users[room]:
                    online_users[room].remove(username)
                    send(f'{username} has disconnected.', to=room)
                    
                    # Get room info
                    room_obj = Room.query.filter_by(name=room).first()
                    room_id = room_obj.id if room_obj else None
                    
                    user_profiles = []
                    user_roles = []
                    
                    if online_users[room]:
                        for u in online_users[room]:
                            user_obj = User.query.filter_by(username=u).first()
                            if user_obj:
                                # Get profile pic
                                profile_pic = user_obj.profile_pic if hasattr(user_obj, 'profile_pic') else 'default.png'
                                user_profiles.append(profile_pic)
                                
                                # Get role if room exists
                                role = 'member'
                                if room_id:
                                    member = RoomMember.query.filter_by(room_id=room_id, user_id=user_obj.id).first()
                                    if member:
                                        role = member.role
                                
                                user_roles.append(role)
                            else:
                                user_profiles.append('default.png')
                                user_roles.append('member')
                    
                    socketio.emit('user_list', {
                        'users': online_users[room],
                        'user_profiles': user_profiles,
                        'user_roles': user_roles
                    }, to=room)
                    
                    # Also remove from typing users
                    if room in typing_users and username in typing_users[room]:
                        typing_users[room].remove(username)
                        socketio.emit('typing', {'users': typing_users[room]}, to=room)

if __name__ == '__main__':
    with app.app_context():
        # First create all database tables
        db.create_all()  
        
        # Then add default topics if they don't exist
        default_topics = [
            {'name': 'General', 'description': 'General discussions', 'icon': 'fas fa-globe'},
            {'name': 'Tech', 'description': 'Technology discussions', 'icon': 'fas fa-laptop-code'},
            {'name': 'Gaming', 'description': 'Gaming discussions', 'icon': 'fas fa-gamepad'},
            {'name': 'Music', 'description': 'Music discussions', 'icon': 'fas fa-music'},
            {'name': 'Sports', 'description': 'Sports discussions', 'icon': 'fas fa-futbol'},
            {'name': 'Art', 'description': 'Art and creativity', 'icon': 'fas fa-paint-brush'}
        ]
        
        for topic_data in default_topics:
            topic = Topic.query.filter_by(name=topic_data['name']).first()
            if not topic:
                new_topic = Topic(
                    name=topic_data['name'],
                    description=topic_data['description'],
                    icon=topic_data['icon']
                )
                db.session.add(new_topic)
        
        # Finally commit all changes
        db.session.commit()
    

    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)  # Set debug=False for production