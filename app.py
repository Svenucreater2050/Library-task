from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    author = db.Column(db.String(120), nullable=False)
    is_available = db.Column(db.Boolean, default=True)

class BorrowRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(50), default="Pending")

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(email=data['email'], password=hashed_password, is_admin=data.get('is_admin', False))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'id': user.id, 'is_admin': user.is_admin})
        return jsonify(access_token=access_token), 200
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/books', methods=['GET'])
@jwt_required()
def get_books():
    books = Book.query.all()
    return jsonify([{"id": book.id, "title": book.title, "author": book.author, "is_available": book.is_available} for book in books]), 200

@app.route('/borrow', methods=['POST'])
@jwt_required()
def borrow_book():
    user_identity = get_jwt_identity()
    data = request.json
    book = Book.query.get(data['book_id'])

    # Check book availability
    if not book or not book.is_available:
        return jsonify({"error": "Book not available"}), 400

    # Check overlapping borrow requests
    overlapping = BorrowRequest.query.filter(
        BorrowRequest.book_id == data['book_id'],
        BorrowRequest.status == "Approved",
        BorrowRequest.start_date <= datetime.strptime(data['end_date'], '%Y-%m-%d'),
        BorrowRequest.end_date >= datetime.strptime(data['start_date'], '%Y-%m-%d')
    ).first()
    if overlapping:
        return jsonify({"error": "Book already borrowed for the requested dates"}), 400

    borrow_request = BorrowRequest(
        user_id=user_identity['id'],
        book_id=data['book_id'],
        start_date=datetime.strptime(data['start_date'], '%Y-%m-%d'),
        end_date=datetime.strptime(data['end_date'], '%Y-%m-%d'),
        status="Pending"
    )
    db.session.add(borrow_request)
    db.session.commit()
    return jsonify({"message": "Borrow request submitted"}), 201

@app.route('/borrow/history', methods=['GET'])
@jwt_required()
def borrow_history():
    user_identity = get_jwt_identity()
    requests = BorrowRequest.query.filter_by(user_id=user_identity['id']).all()
    return jsonify([{
        "book_id": req.book_id,
        "start_date": req.start_date,
        "end_date": req.end_date,
        "status": req.status
    } for req in requests]), 200

@app.route('/admin/requests', methods=['GET'])
@jwt_required()
def view_requests():
    user_identity = get_jwt_identity()
    if not user_identity['is_admin']:
        return jsonify({"error": "Admin access required"}), 403

    requests = BorrowRequest.query.all()
    return jsonify([{
        "id": req.id,
        "user_id": req.user_id,
        "book_id": req.book_id,
        "start_date": req.start_date,
        "end_date": req.end_date,
        "status": req.status
    } for req in requests]), 200

@app.route('/admin/approve/<int:request_id>', methods=['POST'])
@jwt_required()
def approve_request(request_id):
    user_identity = get_jwt_identity()
    if not user_identity['is_admin']:
        return jsonify({"error": "Admin access required"}), 403

    borrow_request = BorrowRequest.query.get(request_id)
    if not borrow_request:
        return jsonify({"error": "Request not found"}), 404

    borrow_request.status = "Approved"
    book = Book.query.get(borrow_request.book_id)
    book.is_available = False
    db.session.commit()
    return jsonify({"message": "Request approved"}), 200

# Initialize DB
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
