from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import jwt
from dotenv import load_dotenv
import os

# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "database.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('JWT_SECRET_KEY')  # Get the secret key from the .env file

db = SQLAlchemy(app)

# Table 1: User Model
class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='User')  # Admin or User

# Initialize the database (for testing purposes)
with app.app_context():
    db.create_all()

# Token validation decorator
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
    email = data.get('email')
    password = data.get('password')

    # Find the user by email
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password_hash, password):
        # Generate JWT token
        token = jwt.encode({
            'user_id': user.user_id,
            'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
        }, app.secret_key, algorithm="HS256")
        
        return jsonify({'message': 'Login successful!', 'token': token}), 200
    else:
        return jsonify({'message': 'Invalid email or password!'}), 400

# Protected Route (Example)
@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        'user_id': current_user.user_id,
        'username': current_user.username,
        'email': current_user.email
    })

# Run the app
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)

