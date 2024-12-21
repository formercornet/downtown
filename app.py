from flask import Flask, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import jwt
import os
from dotenv import load_dotenv
from flask_oauthlib import OAuth
from flask_login import LoginManager, login_user, UserMixin
from urllib.parse import urljoin

# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "database.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('JWT_SECRET_KEY')  # Get the secret key from the .env file

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

db = SQLAlchemy(app)

oauth = OAuth()
oauth.init_app(app)
login_manager = LoginManager(app)

google = oauth.remote_app(
    'google',
    consumer_key=GOOGLE_CLIENT_ID,
    consumer_secret=GOOGLE_CLIENT_SECRET,
    request_token_params={'scope': 'email'},
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth'
)

# Enable CORS for the app
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow requests from any origin

# Table 1: User Model
class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='User')  # Admin or User

class Post(db.Model):
    id = db.Column(db.String, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    comments = db.relationship('Comment', backref='post', lazy=True)
    media_type = db.Column(db.String(50), nullable=True)
    media_uri = db.Column(db.String(255), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'author': self.author,
            'upvotes': self.upvotes,
            'downvotes': self.downvotes,
            'timestamp': self.timestamp.isoformat(),
            'comments': [comment.to_dict() for comment in self.comments],
            'media': {'type': self.media_type, 'uri': self.media_uri} if self.media_uri else None
        }

class Comment(db.Model):
    id = db.Column(db.String, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    post_id = db.Column(db.String, db.ForeignKey('post.id'), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'author': self.author,
            'timestamp': self.timestamp.isoformat()
        }

# Initialize the database (for testing purposes)
with app.app_context():
    db.create_all()

@app.route('/auth/google')
def google_login():
    return google.authorize(callback=url_for('google_callback', _external=True))

@app.route('/auth/google/callback')
def google_callback():
    resp = google.authorized_response()
    if resp is None or 'access_token' not in resp:
        return 'Access denied', 403

    session['google_token'] = (resp['access_token'], '')
    user_info = google.get('userinfo').data
    email = user_info['email']
    
    # Check if the user already exists in the database
    existing_user = User.query.filter_by(email=email).first()
    if not existing_user:
        # Create a new user if they don't exist
        new_user = User(username=user_info['name'], email=email, password_hash=None)
        db.session.add(new_user)
        db.session.commit()

    # Process the user information (e.g., log them in)
    return 'Logged in successfully', 200
    

@google.tokengetter
def get_google_token():
    return session.get('google_token')
