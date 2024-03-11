from flask import Flask, request, jsonify, send_from_directory
import pymysql
import bcrypt
import jwt
from datetime import datetime, timedelta
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import smtplib
from email.mime.text import MIMEText
from flask_mail import Mail, Message
app = Flask(__name__)
CORS(app)
# Database configuration
database_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'admin',
    'database': 'dbsalon',
    'cursorclass': pymysql.cursors.DictCursor
}

# Secret key for JWT
SECRET_KEY = 'salon_key'


def generate_reset_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=20))
import random

def generate_otp():
    # Generate a random 6-digit OTP
    return ''.join(random.choices('0123456789', k=6))


# Function to execute database query
def execute_query(query, params=None, fetchone=False):
    conn = pymysql.connect(**database_config)
    cursor = conn.cursor()
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        conn.commit()
        if fetchone:
            result = cursor.fetchone()
        else:
            result = cursor.fetchall()
    except Exception as e:
        print(f"Error executing query: {e}")
        conn.rollback()
        result = None
    finally:
        conn.close()
    return result

# Function to generate JWT token
def generate_token(user_id):
    payload = {
        'exp': datetime.utcnow() + timedelta(days=1),
        'iat': datetime.utcnow(),
        'sub': user_id
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'anuragreddy345@gmail.com'  # Update with your email
app.config['MAIL_PASSWORD'] = 'ehot arkp jsgr urnv'         # Update with your password
mail = Mail(app)

# Signup route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    firstName = data.get('firstName')
    lastName = data.get('lastName')
    email = data.get('email')
    phoneNumber = data.get('phoneNumber')
    password = data.get('password')
    bcrypt_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    check_email_query = """SELECT * FROM tbusers WHERE email=%s"""
    exists = execute_query(check_email_query, (email,), fetchone=True)
    if exists:
        return {'message': 'Email already exists'}, 400
    insert_query = """
    INSERT INTO tbusers (firstName, lastName, email, phoneNumber, password)
    VALUES (%s, %s, %s, %s, %s)
    """
    parameters = (firstName, lastName, email, phoneNumber, bcrypt_password)
    execute_query(insert_query, parameters)
    return jsonify({'message': 'User created successfully'}), 200

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    query = """SELECT * FROM tbusers WHERE email=%s"""
    user_details = execute_query(query, (email,), fetchone=True)
    if user_details:
        hashed_password_db = user_details['password']
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password_db.encode('utf-8')):
            user_id = user_details['userId']
            token = generate_token(user_id)
            return jsonify({'token': token}), 200
        else:
            return jsonify({'message': 'Invalid email or password'}), 401
    else:
        return jsonify({'message': 'User not found'}), 401

users = {
    'user1@example.com': {
        'password': generate_password_hash('password123'),  # Change 'password_hash' to 'password'
        'reset_token': None
    },
    # Add more users as needed
}

def send_reset_email(user_email, reset_token):
    try:
        # Retrieve user details from the database
        user_details = get_user_details_by_email(user_email)

        if not user_details:
            print("User details not found")
            return False

        message_body = f"""
        To reset your password, click the following link:
        http://localhost:3000/updatepassword?token={reset_token}
        """
        msg = Message('Password Reset', sender='your_email@example.com', recipients=[user_email])
        msg.body = message_body
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending reset email: {e}")
        return False

# Function to retrieve user details by email from the database
def get_user_details_by_email(email):
    # Your database query logic here to fetch user details by email
    # Return user details as a dictionary
    # For example, return {'email': 'user@example.com', 'reset_token': 'random_token'}
    user_details = execute_query("SELECT * FROM tbusers WHERE email=%s", (email,), fetchone=True)
    return user_details

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    # Check if email exists in the database
    user_details = execute_query("SELECT * FROM tbusers WHERE email=%s", (email,), fetchone=True)
    if not user_details:
        return jsonify({'message': 'Email address not found'}), 404

    # Generate OTP and reset token
    otp = generate_otp()
    reset_token = generate_reset_token()

    # Store OTP and Reset Token in user table
    update_query = "UPDATE tbusers SET reset_otp = %s, reset_token = %s WHERE email = %s"
    execute_query(update_query, (otp, reset_token, email))

    # Send OTP via email
    send_reset_email(email, reset_token)

    return jsonify({'message': 'OTP sent to your email', 'reset_token': reset_token, 'otp': otp}), 200


# Function to handle reset password request
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    reset_token = data.get('token')  # Ensure 'token' key is used to retrieve the reset token
    new_password = data.get('password')
    confirm_password = data.get('confirm_password')
    
    # Validate reset token
    if not reset_token:
        return jsonify({'message': 'Reset token is required'}), 400

    # Check if passwords match
    if new_password != confirm_password:
        return jsonify({'message': 'Passwords do not match'}), 400

    # Find user by reset token
    user_details = get_user_details_by_reset_token(reset_token)
    if not user_details:
        return jsonify({'message': 'Invalid reset token'}), 400

    # Update password
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    update_query = "UPDATE tbusers SET password = %s, reset_token = NULL WHERE userId = %s"
    execute_query(update_query, (hashed_password, user_details['userId']))
    
    return jsonify({'message': 'Password updated successfully'}), 200

def get_user_details_by_reset_token(reset_token):
    # Your database query logic here to fetch user details by reset token
    # Return user details as a dictionary
    # For example, return {'email': 'user@example.com', 'userId': 123}
    user_details = execute_query("SELECT * FROM tbusers WHERE reset_token=%s", (reset_token,), fetchone=True)
    return user_details

@app.route('/profile', methods=['GET'])
def profile():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    try:
        decode_token = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
        user_id = decode_token['sub']
        query = "SELECT * FROM tbusers WHERE userId=%s"
        user_details = execute_query(query, (user_id,), fetchone=True)
        if user_details:
            user_profile = {
                'userId': user_details['userId'],
                'firstName': user_details['firstName'],
                'lastName': user_details['lastName'],
                'email': user_details['email'],
                'phoneNumber': user_details['phoneNumber']
            }
            return jsonify(user_profile), 200
        else:
            return jsonify({'message': 'User not found'}), 404
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Expired token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/store', methods=['POST'])
def create_store():
    data = request.json
    storeName = data.get('storeName')
    storeState = data.get('storeState')
    storeCity = data.get('storeCity')
    storeAddress = data.get('storeAddress')
    storePhoneNumber = data.get('storePhoneNumber')
    storeTiming = data.get('storeTiming')

    insert_query = """
    INSERT INTO tbstore (storeName, storeState, storeCity, storeAddress, storePhoneNumber, storeTiming)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    parameters = (storeName, storeState, storeCity, storeAddress, storePhoneNumber, storeTiming)
    execute_query(insert_query, parameters)
    return jsonify({'message': 'Store created successfully'}), 200

# Route for retrieving store details
@app.route('/getstore', methods=['GET'])
def get_store_details():
    try:
        query = "SELECT * FROM tbstore"
        store_details = execute_query(query)
        return jsonify(store_details), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/appointment', methods=['POST'])
def create_appointment():
    token = request.headers.get('Authorization')
    try:
        decoded_token = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
        userId = decoded_token['sub']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Expired token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    data = request.json
    storeId = data.get('storeId')
    appointmentDate = data.get('appointmentDate')
    appointmentTime = data.get('appointmentTime')
    appointmentFor = data.get('appointmentFor')
    employeeId = data.get('employeeId')  # New field for employee ID

    if not storeId or not appointmentDate or not appointmentTime or not appointmentFor or not employeeId:
        return jsonify({'message': 'All fields are required'}), 400

    insert_query = """
    INSERT INTO tbappointments (userId, storeId, appointmentDate, appointmentTime, appointmentFor, employee_id)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    parameters = (userId, storeId, appointmentDate, appointmentTime, appointmentFor, employeeId)
    execute_query(insert_query, parameters)
    
    return jsonify({'message': 'Appointment created successfully'}), 200

# Route for fetching user appointments
@app.route('/user-appointments', methods=['GET'])
def get_user_appointments():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    try:
        decoded_token = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
        user_id = decoded_token['sub']
        query = """
        SELECT a.*, s.storeName, s.storeCity, s.storeAddress, e.Name AS employeeName
        FROM tbappointments a
        INNER JOIN tbstore s ON a.storeId = s.storeId
        INNER JOIN employees e ON a.employee_id = e.EmployeeID
        WHERE a.userId = %s
        """
        user_appointments = execute_query(query, (user_id,))
        
        for appointment in user_appointments:
            appointment['appointmentDate'] = str(appointment['appointmentDate'])
            appointment['appointmentTime'] = str(appointment['appointmentTime'])
        
        return jsonify(user_appointments), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Expired token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ensure the uploads directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Route for serving images
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/products', methods=['POST'])
def add_product():
    # Parse form data
    product_name = request.form.get('productName')
    product_details = request.form.get('productDescription')
    product_price = request.form.get('productPrice')

    # Check if all required form fields are present
    if not (product_name and product_details and product_price):
        return jsonify({'message': 'Missing required form fields'}), 400

    # Handle file upload
    if 'imageFile' not in request.files:
        return jsonify({'message': 'Image file is required'}), 400
    
    image_file = request.files['imageFile']
    if image_file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    # Save the uploaded image file
    if image_file and allowed_file(image_file.filename):
        filename = secure_filename(image_file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(filepath)
    else:
        return jsonify({'message': 'Invalid image file'}), 400

    # Insert product data into the database
    insert_query = """
    INSERT INTO products (product_name, product_details, product_price, image_url)
    VALUES (%s, %s, %s, %s)
    """
    parameters = (product_name, product_details, product_price, filepath)
    try:
        execute_query(insert_query, parameters)
        return jsonify({'message': 'Product added successfully', 'image_url': filepath}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# Route for fetching product details
@app.route('/getproducts', methods=['GET'])
def get_products():
    try:
        query = "SELECT * FROM products"
        products = execute_query(query)
        return jsonify(products), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for updating product details by product ID
@app.route('/products/<int:product_id>', methods=['PUT'])
def update_product(product_id):
    data = request.json
    
    # Extract updated product details
    product_name = data.get('product_name')
    product_details = data.get('product_details')
    product_price = data.get('product_price')

    # Validate input data
    if not product_name or not product_details or not product_price:
        return jsonify({'message': 'All fields are required'}), 400
    
    try:
        # Update the product in the database
        update_query = """
        UPDATE products 
        SET product_name=%s, product_details=%s, product_price=%s
        WHERE id=%s
        """
        parameters = (product_name, product_details, product_price, product_id)
        execute_query(update_query, parameters)
        
        return jsonify({'message': 'Product details updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    try:
        delete_query = "DELETE FROM products WHERE id = %s"
        execute_query(delete_query, (product_id,))
        return jsonify({'message': 'Product deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/cart', methods=['POST'])
def add_to_cart():
    token = request.headers.get('Authorization')
    
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    
    try:
        decoded_token = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
        user_id = decoded_token['sub']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Expired token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    
    data = request.json
    product_id = data.get('productId')
    quantity = data.get('quantity')

    if not product_id or not quantity:
        return jsonify({'message': 'Both productId and quantity are required'}), 400
    
    try:
        product_query = "SELECT * FROM products WHERE id = %s"
        product = execute_query(product_query, (product_id,), fetchone=True)
        if not product:
            return jsonify({'message': 'Product not found'}), 404
        
        total_cost = product['product_price'] * quantity
        
        insert_query = """
        INSERT INTO cart (userId, productId, quantity, total)
        VALUES (%s, %s, %s, %s)
        """
        parameters = (user_id, product_id, quantity, total_cost)
        execute_query(insert_query, parameters)
        
        return jsonify({'message': 'Item added to cart successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/getcart', methods=['GET'])
def get_cart():
    token = request.headers.get('Authorization')
    
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    
    try:
        decoded_token = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
        user_id = decoded_token['sub']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Expired token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    
    try:
        query = """
        SELECT c.*, p.product_name AS productName, p.product_price AS productPrice, p.image_url AS imageUrl
        FROM cart c
        INNER JOIN products p ON c.productId = p.id
        WHERE c.userId = %s
        """
        cart_items = execute_query(query, (user_id,))
        
        if not cart_items:
            return jsonify({'message': 'Cart is empty'}), 404
        
        return jsonify(cart_items), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cart/<int:item_id>', methods=['DELETE'])
def delete_cart_item(item_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    
    try:
        decoded_token = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
        user_id = decoded_token['sub']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Expired token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    
    try:
        check_query = "SELECT * FROM cart WHERE id = %s AND userId = %s"
        item = execute_query(check_query, (item_id, user_id), fetchone=True)
        if not item:
            return jsonify({'message': 'Cart item not found'}), 404
        
        delete_query = "DELETE FROM cart WHERE id = %s"
        execute_query(delete_query, (item_id,))
        
        return jsonify({'message': 'Cart item deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/checkout', methods=['POST'])
def checkout():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    
    try:
        decoded_token = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
        user_id = decoded_token['sub']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Expired token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    
    data = request.json
    cart_ids = data.get('cartId')
    card_name = data.get('card_name')
    card_number = data.get('card_number')
    exp_month = data.get('exp_month')
    exp_year = data.get('exp_year')
    delivery_address = data.get('Delivery_address')
    state = data.get('State')
    city = data.get('City')
    total = data.get('Total')
    pincode = data.get('Pincode')
    status = 'Pending'

    if not cart_ids or not card_name or not card_number or not exp_month or not exp_year or not delivery_address or not state or not city or not total or not pincode:
        return jsonify({'message': 'Missing required fields'}), 400
    
    try:
        # Validate cart items and retrieve productIds
        product_ids = []
        for cart_id in cart_ids:
            check_query = "SELECT * FROM cart WHERE id = %s AND userId = %s"
            item = execute_query(check_query, (cart_id, user_id), fetchone=True)
            if not item:
                return jsonify({'message': f'Cart item with ID {cart_id} not found for the user'}), 404
            product_ids.append(item['productId'])
        
        # Insert checkout details into the database
        insert_query = """
            INSERT INTO checkout (userId, productId, cartId, card_name, card_number, exp_month, exp_year, Delivery_address, State, City, Total, Pincode, Status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        for cart_id, product_id in zip(cart_ids, product_ids):
            parameters = (user_id, product_id, cart_id, card_name, card_number, exp_month, exp_year, delivery_address, state, city, total, pincode, status)
            execute_query(insert_query, parameters)
        
        # Clear the cart
        for cart_id in cart_ids:
            delete_query = "DELETE FROM cart WHERE id = %s"
            execute_query(delete_query, (cart_id,))
        
        return jsonify({'message': 'Order placed successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/user-orders', methods=['GET'])
def get_user_orders():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    try:
        decoded_token = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
        user_id = decoded_token['sub']
        query = """
        SELECT ch.*, 
               p.product_name AS productName, 
               p.image_url AS imageUrl, 
               p.product_price AS productPrice, 
               CONCAT(u.firstName, ' ', u.lastName) AS userName
        FROM checkout ch
        INNER JOIN products p ON ch.productId = p.id
        INNER JOIN tbusers u ON ch.userId = u.userId
        WHERE ch.userId = %s
        """
        user_orders = execute_query(query, (user_id,))
        
        if not user_orders:
            return jsonify({'message': 'No orders found'}), 404
        
        # Convert datetime objects to string for JSON serialization
        for order in user_orders:
            order['Date'] = str(order['Date'])
            order['imageUrl'] = request.host_url + order['imageUrl']  # Append host URL to image URL
        
        return jsonify(user_orders), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Expired token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for retrieving store details by store ID
@app.route('/store/<int:store_id>', methods=['GET'])
def get_store(store_id):
    try:
        query = "SELECT * FROM tbstore WHERE storeId = %s"
        store_details = execute_query(query, (store_id,), fetchone=True)
        if not store_details:
            return jsonify({'message': 'Store not found'}), 404
        return jsonify(store_details), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for updating store details by store ID
@app.route('/store/<int:store_id>', methods=['PUT'])
def update_store(store_id):
    data = request.json
    storeName = data.get('storeName')
    storeState = data.get('storeState')
    storeCity = data.get('storeCity')
    storeAddress = data.get('storeAddress')
    storePhoneNumber = data.get('storePhoneNumber')
    storeTiming = data.get('storeTiming')

    if not storeName or not storeState or not storeCity or not storeAddress or not storePhoneNumber or not storeTiming:
        return jsonify({'message': 'All fields are required'}), 400

    try:
        update_query = """
        UPDATE tbstore 
        SET storeName=%s, storeState=%s, storeCity=%s, storeAddress=%s, storePhoneNumber=%s, storeTiming=%s
        WHERE storeId=%s
        """
        parameters = (storeName, storeState, storeCity, storeAddress, storePhoneNumber, storeTiming, store_id)
        execute_query(update_query, parameters)
        return jsonify({'message': 'Store details updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for deleting a store by store ID
@app.route('/store/<int:store_id>', methods=['DELETE'])
def delete_store(store_id):
    try:
        delete_query = "DELETE FROM tbstore WHERE storeId = %s"
        execute_query(delete_query, (store_id,))
        return jsonify({'message': 'Store deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/employees', methods=['POST'])
def add_employee():
    data = request.json
    name = data.get('name')
    specialist = data.get('specialist')

    if not name:
        return jsonify({'message': 'Name is required'}), 400

    # Insert employee into the database
    query = "INSERT INTO employees (Name, Specialist) VALUES (%s, %s)"
    values = (name, specialist)
    try:
        execute_query(query, values)
        return jsonify({'message': 'Employee added successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/getEmployees', methods=['GET'])
def get_employees():
    try:
        query = "SELECT * FROM employees"
        employees = execute_query(query)
        return jsonify(employees), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/employees/<int:employee_id>', methods=['PUT'])
def update_employee(employee_id):
    data = request.json
    name = data.get('name')
    specialist = data.get('specialist')

    if not name:
        return jsonify({'message': 'Name is required'}), 400

    # Update employee in the database
    update_query = "UPDATE employees SET Name = %s, Specialist = %s WHERE EmployeeID = %s"
    values = (name, specialist, employee_id)
    try:
        execute_query(update_query, values)
        return jsonify({'message': 'Employee updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/employees/<int:employee_id>', methods=['DELETE'])
def delete_employee(employee_id):
    try:
        # Check if the employee exists
        check_query = "SELECT * FROM employees WHERE EmployeeID = %s"
        employee = execute_query(check_query, (employee_id,), fetchone=True)
        if not employee:
            return jsonify({'message': 'Employee not found'}), 404

        # Delete the employee from the database
        delete_query = "DELETE FROM employees WHERE EmployeeID = %s"
        execute_query(delete_query, (employee_id,))
        
        return jsonify({'message': 'Employee deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
