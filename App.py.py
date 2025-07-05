
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os

app = Flask(__name__)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///twitter_clone.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super_secret_key')
app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    bio = db.Column(db.String(280))
    posts = db.relationship('Post', backref='author', lazy=True)
    replies = db.relationship('Reply', backref='replier', lazy=True)

    following = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic'
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'bio': self.bio
        }

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(280), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    media_url = db.Column(db.String(255))
    likes = db.relationship('Like', backref='post', lazy=True, cascade="all, delete-orphan")
    replies = db.relationship('Reply', backref='post', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'username': self.author.username,
            'media_url': self.media_url,
            'likes_count': len(self.likes)
        }

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='_user_post_uc'),)

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(280), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'username': self.replier.username
        }

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing fields'}), 400
    if User.query.filter_by(username=data['username']).first() or User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'User already exists'}), 409
    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered', 'user': user.to_dict()}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    access_token = create_access_token(identity=user.id)
    return jsonify({'access_token': access_token})

@app.route('/me', methods=['GET'])
@jwt_required()
def me():
    user = User.query.get(get_jwt_identity())
    return jsonify(user.to_dict())

@app.route('/posts', methods=['POST'])
@jwt_required()
def create_post():
    user_id = get_jwt_identity()
    data = request.get_json()
    if not data or not data.get('content'):
        return jsonify({'message': 'Content required'}), 400
    if len(data['content']) > 280:
        return jsonify({'message': 'Content exceeds 280 characters'}), 400
    post = Post(content=data['content'], user_id=user_id, media_url=data.get('media_url'))
    db.session.add(post)
    db.session.commit()
    return jsonify({'message': 'Post created', 'post': post.to_dict()}), 201

@app.route('/posts', methods=['GET'])
@jwt_required()
def get_posts():
    user = User.query.get(get_jwt_identity())
    followed_ids = [u.id for u in user.following] + [user.id]
    posts = Post.query.filter(Post.user_id.in_(followed_ids)).order_by(Post.timestamp.desc()).all()
    return jsonify([p.to_dict() for p in posts])

@app.route('/posts/<int:post_id>/like', methods=['POST'])
@jwt_required()
def like_post(post_id):
    user_id = get_jwt_identity()
    if Like.query.filter_by(user_id=user_id, post_id=post_id).first():
        return jsonify({'message': 'Already liked'}), 409
    like = Like(user_id=user_id, post_id=post_id)
    db.session.add(like)
    db.session.commit()
    return jsonify({'message': 'Post liked'})

@app.route('/posts/<int:post_id>/reply', methods=['POST'])
@jwt_required()
def reply_post(post_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    if not data or not data.get('content'):
        return jsonify({'message': 'Content required'}), 400
    reply = Reply(content=data['content'], user_id=user_id, post_id=post_id)
    db.session.add(reply)
    db.session.commit()
    return jsonify({'message': 'Reply added', 'reply': reply.to_dict()}), 201

@app.route('/users/<int:user_id>/follow', methods=['POST'])
@jwt_required()
def follow_user(user_id):
    current_user = User.query.get(get_jwt_identity())
    target_user = User.query.get_or_404(user_id)
    if target_user == current_user:
        return jsonify({'message': 'Cannot follow yourself'}), 400
    if current_user.following.filter(User.id == target_user.id).first():
        return jsonify({'message': 'Already following'}), 409
    current_user.following.append(target_user)
    db.session.commit()
    return jsonify({'message': f'Now following {target_user.username}'})

@app.route('/users/<int:user_id>/unfollow', methods=['POST'])
@jwt_required()
def unfollow_user(user_id):
    current_user = User.query.get(get_jwt_identity())
    target_user = User.query.get_or_404(user_id)
    if target_user == current_user:
        return jsonify({'message': 'Cannot unfollow yourself'}), 400
    if not current_user.following.filter(User.id == target_user.id).first():
        return jsonify({'message': 'Not following'}), 400
    current_user.following.remove(target_user)
    db.session.commit()
    return jsonify({'message': f'Unfollowed {target_user.username}'})

@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
