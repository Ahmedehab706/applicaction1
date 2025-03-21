import base64
import os
from flask import Flask, jsonify, request
import mysql.connector
import jwt
import datetime
from functools import wraps
import bcrypt

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'test'

# JWT Configuration
secret_key = base64.b64encode(os.urandom(32)).decode('utf-8')
app.config['SECRET_KEY'] =  secret_key  # Replace with a secure key in production

# Initialize MySQL connection
db = mysql.connector.connect(
    host=app.config['MYSQL_HOST'],
    user=app.config['MYSQL_USER'],
    password=app.config['MYSQL_PASSWORD'],
    database=app.config['MYSQL_DB']
)

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token is missing"}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated

# Home route
@app.route('/')
def home():
    return "Welcome to the Flask API!"

# Signup route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('name')
    username = data.get('username')
    password = data.get('password')

    if not name or not username or not password:
        return jsonify({"error": "Missing required fields"}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO Users (name, username, password) VALUES (%s, %s, %s)", (name, username, hashed_password))
        db.commit()
        return jsonify({"message": "User created successfully"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 400
    finally:
        cursor.close()

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            token = jwt.encode({
                'id': user['id'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
            }, app.config['SECRET_KEY'])
            return jsonify({"token": token})
        else:
            return jsonify({"error": "Invalid username or password"}), 401
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 400
    finally:
        cursor.close()

# Update user route (protected)
@app.route('/users/<int:id>', methods=['PUT'])
@token_required
def update_user(id):
    data = request.get_json()
    name = data.get('name')
    username = data.get('username')
    password = data.get('password')

    cursor = db.cursor()
    try:
        if password:
            # Hash the new password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("UPDATE Users SET name = %s, username = %s, password = %s WHERE id = %s", (name, username, hashed_password, id))
        else:
            # Update only name and username
            cursor.execute("UPDATE Users SET name = %s, username = %s WHERE id = %s", (name, username, id))
        db.commit()
        return jsonify({"message": "User updated successfully"})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 400
    finally:
        cursor.close()

# Add product route (protected)
@app.route('/products', methods=['POST'])
@token_required
def add_product():
    data = request.get_json()
    pname = data.get('pname')
    description = data.get('description')
    price = data.get('price')
    stock = data.get('stock')

    if not pname or not price or not stock:
        return jsonify({"error": "Missing required fields"}), 400

    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO Products (pname, description, price, stock) VALUES (%s, %s, %s, %s)", (pname, description, price, stock))
        db.commit()
        return jsonify({"message": "Product added successfully"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 400
    finally:
        cursor.close()

if __name__ == '__main__':
    app.run(debug=True)