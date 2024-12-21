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
from flask_mail import Mail, Message
import itsdangerous


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

# Initialize Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Your email address
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Your email password
mail = Mail(app)

# Initialize the URL serializer
serializer = itsdangerous.URLSafeTimedSerializer(app.secret_key)

# Request Password Reset (Step 1)
@app.route('/request_password_reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    email = data.get('email')

    # Check if the user exists
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User with this email does not exist'}), 404

    # Generate a token with the user's email
    token = serializer.dumps(email, salt='password-reset-salt')

    # Send the token via email
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message('Password Reset Request', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
    msg.body = f'Click the link to reset your password: {reset_url}'
    mail.send(msg)

    return jsonify({'message': 'Password reset email sent!'}), 200

# Reset Password (Step 2 & 3)
@app.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    try:
        # Verify the token
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # Token expires after 1 hour
    except itsdangerous.SignatureExpired:
        return jsonify({'message': 'The token is expired!'}), 400
    except itsdangerous.BadSignature:
        return jsonify({'message': 'Invalid token!'}), 400

    data = request.get_json()
    new_password = data.get('new_password')
    password_confirm = data.get('password_confirm')

    if new_password != password_confirm:
        return jsonify({'message': 'Passwords do not match!'}), 400

    # Update the password in the database
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    
    user.password_hash = generate_password_hash(new_password)
    

    try:
        db.session.commit()  # Ensure the session is committed
        print("Password updated successfully!")  # Debug: confirm commit
    except Exception as e:
        print(f"Error committing to DB: {str(e)}")  # Debug: catch any errors during commit
        return jsonify({'message': 'Error updating password in the database!'}), 500

    return jsonify({'message': 'Password has been reset successfully!'}), 200


# Enable CORS for the app
CORS(app, resources={r"/*": {"origins": "https://downtown-production.up.railway.app"}})  # Allow requests from any origin

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
    # Generate a random state to prevent CSRF
    state = os.urandom(24).hex()  # Generate a unique state
    session['oauth_state'] = state  # Store state in session
    
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri, state=state)  # Pass the state to Google

@app.route('/auth/google/callback')
def google_callback():
    # Get the state from the callback request
    state_in_request = request.args.get('state')
    state_in_session = session.get('oauth_state')

    # Check if the states match to prevent CSRF attacks
    if state_in_request != state_in_session:
        session.clear()  # Clear session in case of CSRF error
        return jsonify({"error": "CSRF attack detected!"}), 400

    # If the states match, proceed to get the token and user info
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
    if not user:
        return jsonify({'message': 'Invalid email or password!'}), 400
        

    if not check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid email or password!'}), 400

    # Generate token
    token = jwt.encode(
        {
            'user_id': user.user_id,
            'exp': datetime.utcnow() + timedelta(hours=1)
        },
        app.secret_key,
        algorithm="HS256"
    )
    return jsonify({'message': 'Login successful!', 'token': token}), 200



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