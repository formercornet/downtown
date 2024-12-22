import pytest
from app import app, db, Post, Comment, User
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer
from io import BytesIO
import os

serializer = URLSafeTimedSerializer(app.secret_key)

@pytest.fixture
def client():
    """Create a test client."""
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # In-memory DB
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            db.create_all()  # Set up DB
        yield client
        db.drop_all()  # Clean up after test

# Register Route Test
def test_register(client):
    data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password123',
        'password_confirm': 'password123'
    }
    response = client.post('/register', json=data)
    assert response.status_code == 201
    assert b'Registration successful!' in response.data

# Login Route Test
def test_login(client):
    user_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password123',
        'password_confirm': 'password123'
    }
    client.post('/register', json=user_data)

    login_data = {
        'email': 'test@example.com',
        'password': 'password123'
    }
    response = client.post('/login', json=login_data)
    assert response.status_code == 200
    assert b'Login successful!' in response.data

# Password Reset Tests
def test_request_password_reset(client):
    user_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password123',
        'password_confirm': 'password123'
    }
    client.post('/register', json=user_data)

    reset_data = {'email': 'test@example.com'}
    response = client.post('/request_password_reset', json=reset_data)
    assert response.status_code == 200
    assert b'Password reset email sent!' in response.data

def test_reset_password(client):
    # Register a new user for testing
    user_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password123',
        'password_confirm': 'password123'
    }
    client.post('/register', json=user_data)

    # Generate a real token for password reset using the serializer
    token = serializer.dumps('test@example.com', salt='password-reset-salt')

    # Prepare the reset data
    reset_data = {
        'token': token,
        'new_password': 'newpassword123',
        'password_confirm': 'newpassword123'
    }

    # Perform the password reset request
    response = client.post('/reset_password', json=reset_data)

    # Assert that the response status code is 200 (OK)
    assert response.status_code == 200
    assert response.json['message'] == 'Password has been reset successfully!'

# def test_get_posts(client):
#     # Create a sample post to ensure there is data to fetch
#     post_data = {
#         'content': 'This is a test post',
#         'author_id': 1,  # Assuming author_id is used instead of author name
#         'media': {'type': 'image', 'uri': 'http://example.com/image.jpg'}
#     }
#     client.post('/posts', json=post_data)

#     # Make a GET request to fetch the posts
#     response = client.get('/posts')
    
#     # Assert the status code is 200 OK
#     assert response.status_code == 200

#     # Assert the response is a list of posts
#     posts = response.get_json()
#     assert isinstance(posts, list)
#     assert len(posts) > 0  # Ensure there is at least one post
#     assert 'content' in posts[0]
#     assert 'author_id' in posts[0]

# def test_create_post(client):
#     # Post data to create a new post
#     post_data = {
#         'content': 'This is a test post',
#         'author_id': 1,  # Assuming author_id is used instead of author name
#         'media': {'type': 'image', 'uri': 'http://example.com/image.jpg'}
#     }

#     # Make a POST request to create a new post
#     response = client.post('/posts', json=post_data)
    
#     # Assert the status code is 201 Created
#     assert response.status_code == 201

#     # Assert that the response contains the post data and that the ID is generated
#     post = response.get_json()
#     assert 'id' in post
#     assert post['content'] == 'This is a test post'
#     assert post['author_id'] == 1

# def test_edit_post(client):
#     # First, create a new post
#     post_data = {
#         'content': 'Initial content',
#         'author_id': 1,  # Assuming author_id is used instead of author name
#         'media': {'type': 'image', 'uri': 'http://example.com/image.jpg'}
#     }
#     create_response = client.post('/posts', json=post_data)
#     post = create_response.get_json()

#     # Ensure the post was created successfully
#     assert 'id' in post

#     # Now, edit the content of the post
#     edit_data = {
#         'content': 'Updated content'
#     }

#     # Make a PUT request to update the post
#     response = client.put(f'/posts/{post["id"]}', json=edit_data)
    
#     # Assert the status code is 200 OK
#     assert response.status_code == 200

#     # Assert that the post content has been updated
#     updated_post = response.get_json()
#     assert updated_post['content'] == 'Updated content'

# def test_edit_non_existent_post(client):
#     # Attempt to edit a non-existent post
#     edit_data = {
#         'content': 'Updated content'
#     }

#     # Make a PUT request with a random post ID that doesn't exist
#     response = client.put('/posts/nonexistent_id', json=edit_data)
    
#     # Assert the status code is 404 Not Found
#     assert response.status_code == 404

#     # Assert the response message
#     assert response.json['message'] == 'Post not found'

# def test_vote_on_post(client):
#     # First, create a post
#     post_data = {
#         'content': 'This is a test post',
#         'author_id': 1,  # Assuming author_id is used instead of author name
#         'media': {'type': 'image', 'uri': 'http://example.com/image.jpg'}
#     }
#     create_response = client.post('/posts', json=post_data)
#     post = create_response.get_json()

#     # Ensure the post was created successfully
#     assert 'id' in post

#     # Vote up the post
#     vote_data = {'vote_type': 'up'}
#     response = client.post(f'/posts/{post["id"]}/vote', json=vote_data)

#     # Assert the status code is 200 OK
#     assert response.status_code == 200

#     # Assert the vote count is incremented
#     updated_post = response.get_json()
#     assert updated_post['upvotes'] == 1
#     assert updated_post['downvotes'] == 0

#     # Vote down the post
#     vote_data = {'vote_type': 'down'}
#     response = client.post(f'/posts/{post["id"]}/vote', json=vote_data)

#     # Assert the status code is 200 OK
#     assert response.status_code == 200

#     # Assert the vote count is updated correctly
#     updated_post = response.get_json()
#     assert updated_post['upvotes'] == 1
#     assert updated_post['downvotes'] == 1

def test_upload_media(client):
    # Prepare a mock file (e.g., an image or video file)
    data = {
        'file': (BytesIO(b"fake image content"), 'test_image.jpg'),
        'type': 'image'  # This could be 'image' or 'video'
    }

    # Send a POST request to the upload media endpoint
    response = client.post('/media/upload', data=data, content_type='multipart/form-data')

    # Assert that the response is successful
    assert response.status_code == 201  # Adjusted to match the expected status code
    assert b"Media uploaded successfully" in response.data
    assert b"uri" in response.data

    # Check that the file was saved
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_image.jpg')
    assert os.path.exists(file_path)

    # Cleanup (delete the uploaded file after testing)
    os.remove(file_path)