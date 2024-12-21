from flask import Flask, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import jwt
import os
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth  # Updated import
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

# Initialize OAuth instance
oauth = OAuth(app)  # Updated to use Authlib OAuth
login_manager = LoginManager(app)

# Configure the Google OAuth client
google = oauth.register(
    'google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    refresh_token_url=None,
    client_kwargs={'scope': 'openid profile email'},
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
    # Initiates OAuth flow
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def google_callback():
    # Get the OAuth response and fetch user info
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()

    # Store the token in the session
    session['google_token'] = token

    # Extract email from the response
    email = user_info['email']

    # Check if the user already exists in the database
    existing_user = User.query.filter_by(email=email).first()
    if not existing_user:
        # Create a new user if they don't exist
        new_user = User(username=user_info['name'], email=email, password_hash=None)
        db.session.add(new_user)
        db.session.commit()

    # Log the user in
    user = User.query.filter_by(email=email).first()
    login_user(user)

    return 'Logged in successfully', 200

# Manually define a function to retrieve the Google token if needed
def get_google_token():
    return session.get('google_token')


def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            # Extract the token after "Bearer "
            token = token.split(" ")[1]
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            current_user = User.query.filter_by(user_id=data['user_id']).first()
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated_function

# Registration Route - Simplified for backend testing
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()  # Get data as JSON
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    password_confirm = data.get('password_confirm')

    # Check if passwords match
    if password != password_confirm:
        return jsonify({'message': 'Passwords do not match!'}), 400

    # Check if the email already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'Email already registered!'}), 400

    # Hash the password using werkzeug
    hashed_password = generate_password_hash(password)

    # Create a new user and add to the database
    new_user = User(username=username, email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Registration successful!'}), 201

# Login Route - Generate JWT token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password!'}), 400

    email = data.get('email')
    password = data.get('password')

    # Fetch the user from the database
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid email or password!'}), 400

    try:
        # Generate JWT token
        token = jwt.encode(
            {
                'user_id': user.user_id,
                'exp': datetime.utcnow() + timedelta(hours=1)  # Expiration in 1 hour
            },
            app.secret_key,  # Use the secret key
            algorithm="HS256"
        )

        return jsonify({'message': 'Login successful!', 'token': token}), 200

    except Exception as e:
        return jsonify({'message': 'Token generation failed!', 'error': str(e)}), 500


# Protected Route (Example)
@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        'user_id': current_user.user_id,
        'username': current_user.username,
        'email': current_user.email
    })

# 1. Fetch all posts
@app.route('/posts', methods=['GET'])
def get_posts():
    posts = Post.query.all()
    return jsonify([post.to_dict() for post in posts])

# 2. Create a new post
@app.route('/posts', methods=['POST'])
def create_post():
    data = request.get_json()
    content = data.get('content')
    author = data.get('author')
    media = data.get('media')  # Media should be passed as a dictionary containing type and uri

    if not content or not author:
        return jsonify({"message": "Content and author are required"}), 400

    post = Post(
        id=str(datetime.utcnow().timestamp()),  # Unique ID based on timestamp
        content=content,
        author=author,
        media_type=media['type'] if media else None,
        media_uri=media['uri'] if media else None
    )

    db.session.add(post)
    db.session.commit()

    return jsonify(post.to_dict()), 201

# 3. Edit a post
@app.route('/posts/<post_id>', methods=['PUT'])
def edit_post(post_id):
    post = Post.query.get(post_id)
    if not post:
        return jsonify({"message": "Post not found"}), 404

    data = request.get_json()
    post.content = data.get('content', post.content)

    db.session.commit()

    return jsonify(post.to_dict())

# 4. Add a comment to a post
@app.route('/posts/<post_id>/comments', methods=['POST'])
def add_comment(post_id):
    post = Post.query.get(post_id)
    if not post:
        return jsonify({"message": "Post not found"}), 404

    data = request.get_json()
    comment_content = data.get('content')
    comment_author = data.get('author')

    if not comment_content or not comment_author:
        return jsonify({"message": "Content and author are required"}), 400

    comment = Comment(
        id=str(datetime.utcnow().timestamp()),
        content=comment_content,
        author=comment_author,
        post_id=post_id
    )

    db.session.add(comment)
    db.session.commit()

    return jsonify(comment.to_dict()), 201

# 5. Vote on a post (upvote or downvote)
@app.route('/posts/<post_id>/vote', methods=['POST'])
def vote_on_post(post_id):
    data = request.get_json()
    vote_type = data.get('vote_type')  # "up" or "down"

    if vote_type not in ['up', 'down']:
        return jsonify({"message": "Invalid vote type"}), 400

    post = Post.query.get(post_id)
    if not post:
        return jsonify({"message": "Post not found"}), 404

    if vote_type == 'up':
        post.upvotes += 1
    elif vote_type == 'down':
        post.downvotes += 1

    db.session.commit()

    return jsonify(post.to_dict())

# 6. Upload media (image/video)
@app.route('/media/upload', methods=['POST'])
def upload_media():
    file = request.files['file']
    file_type = request.form.get('type')  # 'image' or 'video'

    if not file or file_type not in ['image', 'video']:
        return jsonify({"message": "Invalid file or type"}), 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)

    return jsonify({"message": "Media uploaded successfully", "uri": file_path, "type": file_type})

# Run the app
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
