from datetime import datetime
import bcrypt
from flask import Flask, jsonify, session, request, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import JSON


app = Flask(__name__)



app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# Configuration
app.config['SECRET_KEY'] = 'your_strong_secret_key'
app.config["JWT_SECRET_KEY"] = 'SmartSolar@123'
app.config['JWT_TOKEN_LOCATION'] = ['headers']

db = SQLAlchemy(app)

# JWT Initialization
jwt = JWTManager(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, default= 'default@gmail.com')
    name = db.Column(db.String(100), nullable=False, default = 'Default')
    country = db.Column(db.String(50), nullable=False, default= "Nepal Default")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean(), default=True)
    contents = db.relationship('Content', backref='user', lazy = True)

    def __repr__(self):
        return f'<User {self.username}>'
    
class Content(db.Model):
    __tablename__ = 'contents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable = False)
    body = db.Column(db.String(500), nullable = False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

with app.app_context():
    db.create_all()
    

@app.route('/content', methods=['GET'])
@jwt_required()
def get_contents():
    contents = Content.query.all()
    content_list = []
    for content in contents:
        content_data={
            "id":content.id,
            "type":"content",
            "attributes":{
                "title":content.title,
                "body": content.body,   
                "createdAt": content.created_at.isoformat(),
                "updatedAt": content.updated_at.isoformat()
            }
            # "relationships": {
            #     "user": {
            #         "id": content.user_id,
            #         "username": content.user.username
            #     }
            # }
        }
        content_list.append(content_data)
    
    response = {
        "data":content_list
    }
    return jsonify(response)

@app.route('/contents', methods=['POST'])
@jwt_required()
def create_content():
    user_id = get_jwt_identity()
    data = request.get_json()
    title = data['title']
    body = data['body']

    new_content = Content(
        title = title,
        body=body,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        user_id=user_id
    )
    
    db.session.add(new_content)
    db.session.commit()

    response = {
        "data": {
            "id": new_content.id,
            "type": "content",
            "attributes":{
                "title": new_content.title,
                "body": new_content.body,
                "createdAt": new_content.created_at.isoformat(),
                "updatedAt": new_content.updated_at.isoformat()
            }
            # "relationships": {
            # "user": {
            #     "id": user_id
            # }
            # }
        }
    }
    
    return jsonify(response), 201


@app.route('/contents/<int:id>', methods=['PUT'])
@jwt_required()
def update_content(id):
    user_id = get_jwt_identity()
    content_update = Content.query.get(id)
    if not content_update:
        return jsonify({"message":"Content not found"}), 404
    
    if content_update.user_id != user_id:
        return jsonify({"message":"Unauthorized"}), 403

    data = request.get_json()
    if 'title' in data:
        content_update.title = data['title']
    if 'body' in data:
        content_update.body = data['body']
    content_update.updated_at = datetime.utcnow()

    db.session.commit()
    content_data = {
        "id": content_update.id,
        "type": "content",
        "attributes": {
            "title": content_update.title,
            "body": content_update.body,
            "createdAt": content_update.created_at.isoformat(),
            "updatedAt": content_update.updated_at.isoformat()
        }
    }
    
    response = {
        "data": content_data
    }
    
    return jsonify(response)

@app.route('/contents/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_content(id):
    user_id = get_jwt_identity()
    content_delete = Content.query.get(id)
    if not content_delete:
        return jsonify({"message": "Content not found"}), 404

    if content_delete.user_id != user_id:
        return jsonify({"message": "Unauthorized"}), 403

    db.session.delete(content_delete)
    db.session.commit()

    return jsonify({"message": "Content deleted successfully"}), 200


@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = User.query.all()
    users_list = []

    for user in users:
        user_data= {
            "id":user.id,
            "username":user.username,
            "email": user.email,
            "name": user.name,
            "country": user.country,
            "createdAt": user.created_at.isoformat(),
            "updatedAt": user.updated_at.isoformat(),
            "is_active": user.is_active
        }
        users_list.append(user_data)

    response = {
        "data":users_list
    }
    return jsonify(response)

    

@app.route('/get_name', methods=['GET'])
@jwt_required()
def get_name():
    # Extract the user ID from the JWT
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()

    # Check if user exists
    if user:
        return jsonify({'message': 'User found', 'name': user.name})
    else:
        return jsonify({'message': 'User not found'}), 404


@app.route('/users/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data.get('email', 'default@example.com')
    name = data.get('name', 'Default Name')
    country = data.get('country', 'Nepal - Default')
    

    # Check if the username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'Username already taken'}), 400
    
    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Create new user
    new_user = User(
        username=username, 
        password=hashed_password.decode('utf-8'),
        email=email,
        name=name,
        country=country,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=new_user.id)

    response = {
        "data": {
            "id": new_user.id,
            "type": "users",
            "attributes":{
                "token":access_token,
                "email": new_user.email,
                "name": new_user.name,
                "country": new_user.country,
                "createdAt": new_user.created_at.isoformat(),
                "updatedAt": new_user.updated_at.isoformat()
            }
        }
    }
    
    return jsonify(response)

@app.route('/auth/signin', methods=['POST'])
def signin():
    data = request.get_json()
    username = data['username']
    password = data['password']
    print('Received data:', username, password)

    user = User.query.filter_by(username=username).first()
    # access_token = create_access_token(identity=user.id)

    if user:
        # Print the stored password hash for debugging
        print('Stored password hash:', user.password)
        
        # Check the password
        if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            access_token = create_access_token(identity=user.id)
            response = {
                "data":{
                    "id":user.id,
                    "type": "users",
                    "attributes":{
                        "token":access_token,
                        "email": user.email,
                        "name": user.name,
                        "country": user.country,
                        "createdAt": user.created_at.isoformat(),
                        "updatedAt": user.updated_at.isoformat()
                    }
                }
            }
            return jsonify(response)
        else:
            print('Password mismatch')
            return jsonify({"message": "Invalid credentials"}), 401
    else:
        print('User not found')
        return jsonify({"message": "Invalid credentials"}), 401

    
if __name__ == "__main__":
    with app.app_context():
        app.run(debug= True, host='0.0.0.0', port=3000)