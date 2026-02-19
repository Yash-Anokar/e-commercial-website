from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import pymysql
from pymysql import Error
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
import string
from datetime import datetime, timedelta
from contextlib import contextmanager
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# Use environment variable for secret key, fallback to default for local development
app.secret_key = os.getenv('SECRET_KEY', 'vasundhara-agro-secret-key-2024')

# Site Configuration
SITE_NAME = "Vasundhara Agro Processing Center"
SITE_LOCATION = "Anjangaon Surji"
SITE_TAGLINE = "Pure Ayurvedic Products from Nature"

# MySQL Database configuration - Use environment variables for production
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', 'Yash#826298'),
    'database': os.getenv('DB_NAME', 'vasundhara_agro_db'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

# OTP storage (in-memory for development, use Redis in production)
otp_storage = {}

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = None
    try:
        conn = pymysql.connect(**DB_CONFIG)
        yield conn
    except Error as e:
        print(f"Database connection error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def init_db():
    """Initialize the database with tables"""
    # First, create the database if it doesn't exist
    try:
        config_without_db = DB_CONFIG.copy()
        config_without_db.pop('database')
        conn = pymysql.connect(**config_without_db)
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        print(f"Database '{DB_CONFIG['database']}' created or already exists.")
        cursor.close()
        conn.close()
    except Error as e:
        print(f"Error creating database: {e}")
        return
    
    # Now connect to the database and create tables
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                is_admin TINYINT(1) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            # Products table
            cursor.execute('''CREATE TABLE IF NOT EXISTS products (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                price DECIMAL(10, 2) NOT NULL,
                image VARCHAR(500),
                stock INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            # Cart table
            cursor.execute('''CREATE TABLE IF NOT EXISTS cart (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE
            )''')
            
            # Orders table with delivery tracking
            cursor.execute('''CREATE TABLE IF NOT EXISTS orders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                customer_name VARCHAR(255),
                customer_phone VARCHAR(20),
                delivery_address TEXT,
                delivery_city VARCHAR(100),
                delivery_pincode VARCHAR(10),
                delivery_instructions TEXT,
                payment_method VARCHAR(50) DEFAULT 'COD',
                tracking_number VARCHAR(100),
                total_amount DECIMAL(10, 2) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                delivery_date TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )''')
            
            # Order items table
            cursor.execute('''CREATE TABLE IF NOT EXISTS order_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                order_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL,
                price DECIMAL(10, 2) NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE
            )''')
            
            # Order status history table
            cursor.execute('''CREATE TABLE IF NOT EXISTS order_status_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                order_id INT NOT NULL,
                status VARCHAR(50) NOT NULL,
                notes TEXT,
                updated_by VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE
            )''')
            
            conn.commit()
            print("Tables created successfully.")
            
            # Create admin user if it doesn't exist
            cursor.execute("SELECT * FROM users WHERE username = 'admin'")
            if not cursor.fetchone():
                admin_password = generate_password_hash('admin123')
                cursor.execute(
                    "INSERT INTO users (username, password, email, is_admin) VALUES (%s, %s, %s, %s)", 
                    ('admin', admin_password, 'admin@example.com', 1)
                )
                conn.commit()
                print("Admin user created: username='admin', password='admin123'")
            
            # Fix NULL customer names in existing orders
            cursor.execute('''
                UPDATE orders o
                JOIN users u ON o.user_id = u.id
                SET o.customer_name = u.username
                WHERE o.customer_name IS NULL
            ''')
            conn.commit()
            if cursor.rowcount > 0:
                print(f"Updated {cursor.rowcount} NULL customer names.")
            
            cursor.close()
    except Error as e:
        print(f"Error initializing database: {e}")

# Initialize database on startup
init_db()

# ============= UTILITY FUNCTIONS =============

def get_user():
    """Get current user from session"""
    return session.get('user')

def generate_otp():
    """Generate 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

def send_otp_sms(phone, message):
    """
    Send SMS (prints to console in development)
    In production, integrate with SMS gateway like Fast2SMS, MSG91, or Twilio
    """
    print(f"\n{'='*60}")
    print(f"📱 SMS to {phone}:")
    print(f"   {message}")
    print(f"{'='*60}\n")
    # Production code would call actual SMS API here
    return True

def login_required(f):
    """Decorator for routes that require login"""
    def decorated_function(*args, **kwargs):
        if not get_user():
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    """Decorator for routes that require admin access"""
    def decorated_function(*args, **kwargs):
        user = get_user()
        if not user or not user.get('is_admin'):
            flash('Admin access required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ============= PUBLIC ROUTES =============

@app.route('/')
def home():
    """Home page with product listing"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM products ORDER BY created_at DESC')
            products = cursor.fetchall()
            cursor.close()
        
        # Convert to tuples for template compatibility
        products_list = []
        for product in products:
            products_list.append((
                product['id'],
                product['name'],
                product['description'],
                float(product['price']),
                product['image']
            ))
        
        return render_template('home.html', 
                             products=products_list, 
                             user=get_user(),
                             site_name=SITE_NAME,
                             site_location=SITE_LOCATION,
                             site_tagline=SITE_TAGLINE)
    except Error as e:
        flash('Error loading products.', 'danger')
        return render_template('home.html', 
                             products=[], 
                             user=get_user(),
                             site_name=SITE_NAME,
                             site_location=SITE_LOCATION,
                             site_tagline=SITE_TAGLINE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        email = request.form.get('email', '').strip()
        
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register.html')
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Check if username already exists
                cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                existing_user = cursor.fetchone()
                
                if existing_user:
                    flash('Username already exists. Please choose a different one.', 'danger')
                    cursor.close()
                    return render_template('register.html')
                
                # Create new user
                hashed_password = generate_password_hash(password)
                cursor.execute(
                    'INSERT INTO users (username, password, email) VALUES (%s, %s, %s)', 
                    (username, hashed_password, email)
                )
                conn.commit()
                cursor.close()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
        except Error as e:
            flash('Registration failed. Please try again.', 'danger')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('login.html')
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                user = cursor.fetchone()
                cursor.close()
            
            if user and check_password_hash(user['password'], password):
                session['user'] = {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'is_admin': bool(user['is_admin'])
                }
                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password.', 'danger')
        except Error as e:
            flash('Login error. Please try again.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """Product detail page"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM products WHERE id = %s', (product_id,))
            product = cursor.fetchone()
            cursor.close()
        
        if not product:
            flash('Product not found.', 'danger')
            return redirect(url_for('home'))
        
        # Convert to tuple for template compatibility
        product_tuple = (
            product['id'],
            product['name'],
            product['description'],
            float(product['price']),
            product['image']
        )
        
        return render_template('product_detail.html', product=product_tuple, user=get_user())
    except Error as e:
        flash('Error loading product.', 'danger')
        return redirect(url_for('home'))

# ============= CART ROUTES =============

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    """Add product to cart"""
    try:
        quantity = int(request.form.get('quantity', 1))
        if quantity <= 0:
            flash('Invalid quantity.', 'danger')
            return redirect(url_for('product_detail', product_id=product_id))
    except ValueError:
        flash('Invalid quantity.', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))
    
    user = get_user()
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if product exists
            cursor.execute('SELECT * FROM products WHERE id = %s', (product_id,))
            product = cursor.fetchone()
            
            if not product:
                flash('Product not found.', 'danger')
                cursor.close()
                return redirect(url_for('home'))
            
            # Check if item is already in cart
            cursor.execute(
                'SELECT * FROM cart WHERE user_id = %s AND product_id = %s', 
                (user['id'], product_id)
            )
            existing_item = cursor.fetchone()
            
            if existing_item:
                # Update quantity
                new_quantity = existing_item['quantity'] + quantity
                cursor.execute(
                    'UPDATE cart SET quantity = %s WHERE user_id = %s AND product_id = %s',
                    (new_quantity, user['id'], product_id)
                )
            else:
                # Add new item
                cursor.execute(
                    'INSERT INTO cart (user_id, product_id, quantity) VALUES (%s, %s, %s)',
                    (user['id'], product_id, quantity)
                )
            
            conn.commit()
            cursor.close()
            flash(f'Added {quantity} {product["name"]} to cart!', 'success')
    except Error as e:
        flash('Error adding to cart.', 'danger')
    
    return redirect(url_for('cart'))

@app.route('/cart')
@login_required
def cart():
    """Shopping cart page"""
    user = get_user()
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT c.id, c.quantity, p.id as product_id, p.name, p.price, p.image
                FROM cart c
                JOIN products p ON c.product_id = p.id
                WHERE c.user_id = %s
                ORDER BY c.created_at DESC
            ''', (user['id'],))
            cart_items = cursor.fetchall()
            cursor.close()
        
        # Convert to tuples for template compatibility
        items = []
        total = 0
        for item in cart_items:
            item_tuple = (
                item['id'],
                item['name'],
                float(item['price']),
                item['quantity'],
                item['product_id']
            )
            items.append(item_tuple)
            total += float(item['price']) * item['quantity']
        
        return render_template('cart.html', items=items, total=total, user=user)
    except Error as e:
        flash('Error loading cart.', 'danger')
        return render_template('cart.html', items=[], total=0, user=user)

@app.route('/remove_from_cart/<int:cart_id>')
@login_required
def remove_from_cart(cart_id):
    """Remove item from cart"""
    user = get_user()
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verify the cart item belongs to the current user
            cursor.execute(
                'SELECT * FROM cart WHERE id = %s AND user_id = %s', 
                (cart_id, user['id'])
            )
            cart_item = cursor.fetchone()
            
            if cart_item:
                cursor.execute('DELETE FROM cart WHERE id = %s', (cart_id,))
                conn.commit()
                flash('Item removed from cart.', 'success')
            else:
                flash('Item not found in cart.', 'danger')
            
            cursor.close()
    except Error as e:
        flash('Error removing item from cart.', 'danger')
    
    return redirect(url_for('cart'))

# ============= CHECKOUT WITH OTP =============

@app.route('/checkout', methods=['GET'])
@login_required
def checkout():
    """Show checkout form with delivery details"""
    user = get_user()
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get cart items
            cursor.execute('''
                SELECT c.quantity, p.id as product_id, p.name, p.price
                FROM cart c
                JOIN products p ON c.product_id = p.id
                WHERE c.user_id = %s
            ''', (user['id'],))
            cart_items = cursor.fetchall()
            cursor.close()
            
            if not cart_items:
                flash('Your cart is empty.', 'warning')
                return redirect(url_for('cart'))
            
            # Calculate total
            total = sum(float(item['price']) * item['quantity'] for item in cart_items)
            
            return render_template('checkout_with_otp.html', 
                                 cart_items=cart_items, 
                                 total=total, 
                                 user=user)
    except Error as e:
        flash('Error loading checkout.', 'danger')
        return redirect(url_for('cart'))

@app.route('/send_otp', methods=['POST'])
@login_required
def send_otp():
    """Send OTP to customer's phone"""
    phone = request.form.get('customer_phone', '').strip()
    
    if not phone or len(phone) != 10:
        return jsonify({'success': False, 'message': 'Invalid phone number'}), 400
    
    # Generate OTP
    otp = generate_otp()
    
    # Store OTP with expiry time (5 minutes)
    otp_storage[phone] = {
        'otp': otp,
        'expires_at': datetime.now() + timedelta(minutes=5),
        'verified': False
    }
    
    # Send OTP via SMS
    if send_otp_sms(phone, f"Your VAPC OTP is {otp}. Valid for 5 minutes."):
        return jsonify({'success': True, 'message': f'OTP sent to {phone}'}), 200
    else:
        return jsonify({'success': False, 'message': 'Failed to send OTP'}), 500

@app.route('/verify_otp', methods=['POST'])
@login_required
def verify_otp():
    """Verify OTP entered by customer"""
    phone = request.form.get('customer_phone', '').strip()
    entered_otp = request.form.get('otp', '').strip()
    
    if phone not in otp_storage:
        return jsonify({'success': False, 'message': 'OTP not sent or expired'}), 400
    
    stored_data = otp_storage[phone]
    
    # Check if OTP expired
    if datetime.now() > stored_data['expires_at']:
        del otp_storage[phone]
        return jsonify({'success': False, 'message': 'OTP expired. Please request a new one.'}), 400
    
    # Verify OTP
    if stored_data['otp'] == entered_otp:
        stored_data['verified'] = True
        return jsonify({'success': True, 'message': 'OTP verified successfully'}), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid OTP. Please try again.'}), 400

@app.route('/process_checkout', methods=['POST'])
@login_required
def process_checkout():
    """Process checkout with OTP verification"""
    user = get_user()
    
    # Get form data
    customer_name = request.form.get('customer_name', '').strip()
    customer_phone = request.form.get('customer_phone', '').strip()
    delivery_address = request.form.get('delivery_address', '').strip()
    delivery_city = request.form.get('delivery_city', '').strip()
    delivery_pincode = request.form.get('delivery_pincode', '').strip()
    delivery_instructions = request.form.get('delivery_instructions', '').strip()
    payment_method = request.form.get('payment_method', 'COD')
    
    # Validate required fields
    if not all([customer_name, customer_phone, delivery_address, delivery_city, delivery_pincode]):
        flash('Please fill all required delivery details.', 'danger')
        return redirect(url_for('checkout'))
    
    # Verify OTP if payment method is Online/UPI
    if payment_method in ['Online', 'UPI']:
        if customer_phone not in otp_storage or not otp_storage[customer_phone].get('verified'):
            flash('Please verify your phone number with OTP first.', 'danger')
            return redirect(url_for('checkout'))
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get cart items
            cursor.execute('''
                SELECT c.quantity, p.id as product_id, p.name, p.price
                FROM cart c
                JOIN products p ON c.product_id = p.id
                WHERE c.user_id = %s
            ''', (user['id'],))
            cart_items = cursor.fetchall()
            
            if not cart_items:
                flash('Your cart is empty.', 'warning')
                cursor.close()
                return redirect(url_for('cart'))
            
            # Calculate total
            total_amount = sum(float(item['price']) * item['quantity'] for item in cart_items)
            
            # Generate tracking number
            tracking_number = 'VAPC' + ''.join(random.choices(string.digits, k=8))
            
            # Create order with delivery details
            cursor.execute('''
                INSERT INTO orders 
                (user_id, customer_name, customer_phone, delivery_address, 
                 delivery_city, delivery_pincode, delivery_instructions, 
                 payment_method, tracking_number, total_amount, status) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (user['id'], customer_name, customer_phone, delivery_address,
                  delivery_city, delivery_pincode, delivery_instructions,
                  payment_method, tracking_number, total_amount, 'confirmed'))
            
            order_id = conn.insert_id()
            
            # Add order items
            for item in cart_items:
                cursor.execute('''
                    INSERT INTO order_items (order_id, product_id, quantity, price) 
                    VALUES (%s, %s, %s, %s)
                ''', (order_id, item['product_id'], item['quantity'], float(item['price'])))
            
            # Log status history
            cursor.execute('''
                INSERT INTO order_status_history (order_id, status, notes, updated_by)
                VALUES (%s, %s, %s, %s)
            ''', (order_id, 'confirmed', f'Order placed. Payment: {payment_method}', customer_name))
            
            # Clear cart
            cursor.execute('DELETE FROM cart WHERE user_id = %s', (user['id'],))
            
            conn.commit()
            cursor.close()
            
            # Clear OTP after successful order
            if customer_phone in otp_storage:
                del otp_storage[customer_phone]
            
            # Send confirmation SMS
            send_otp_sms(customer_phone, 
                        f"Order confirmed! Tracking: {tracking_number}. Total: ₹{total_amount:.2f}")
            
            flash(f'Order placed successfully! Tracking: {tracking_number}', 'success')
            return render_template('checkout.html', user=user)
            
    except Error as e:
        print(f"Checkout error: {e}")
        flash('Error processing order. Please try again.', 'danger')
        return redirect(url_for('cart'))

# ============= ORDER ROUTES =============

@app.route('/orders')
@login_required
def orders():
    """User's order history"""
    user = get_user()
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT o.id, o.total_amount, o.status, o.created_at, o.tracking_number,
                       GROUP_CONCAT(CONCAT(p.name, ' (x', oi.quantity, ')') SEPARATOR ', ') as items
                FROM orders o
                LEFT JOIN order_items oi ON o.id = oi.order_id
                LEFT JOIN products p ON oi.product_id = p.id
                WHERE o.user_id = %s
                GROUP BY o.id
                ORDER BY o.created_at DESC
            ''', (user['id'],))
            user_orders = cursor.fetchall()
            cursor.close()
        
        # Convert to tuples for template compatibility
        orders_list = []
        for order in user_orders:
            order_tuple = (
                order['id'],
                order['items'] if order['items'] else 'No items',
                1,  # quantity placeholder
                float(order['total_amount'])
            )
            orders_list.append(order_tuple)
        
        return render_template('orders.html', orders=orders_list, user=user)
    except Error as e:
        flash('Error loading orders.', 'danger')
        return render_template('orders.html', orders=[], user=user)

@app.route('/track_order/<tracking_number>')
@login_required
def track_order(tracking_number):
    """Track order by tracking number"""
    user = get_user()
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT o.*, 
                       GROUP_CONCAT(CONCAT(p.name, ' x', oi.quantity) SEPARATOR ', ') as items
                FROM orders o
                JOIN order_items oi ON o.id = oi.order_id
                JOIN products p ON oi.product_id = p.id
                WHERE o.tracking_number = %s AND o.user_id = %s
                GROUP BY o.id
            ''', (tracking_number, user['id']))
            order = cursor.fetchone()
            cursor.close()
            
        if not order:
            flash('Order not found or access denied.', 'danger')
            return redirect(url_for('orders'))
            
        return render_template('track_order.html', order=order, user=user)
    except Error as e:
        flash('Error tracking order.', 'danger')
        return redirect(url_for('orders'))

# ============= ADMIN PRODUCT MANAGEMENT =============

@app.route('/add_product', methods=['GET', 'POST'])
@admin_required
def add_product():
    """Add new product (Admin only)"""
    if request.method == 'POST':
        name = request.form['name'].strip()
        description = request.form['description'].strip()
        price = request.form['price']
        image = request.form['image'].strip()
        stock = request.form.get('stock', 0)
        
        if not name or not price:
            flash('Name and price are required.', 'danger')
            return render_template('add_product.html', user=get_user())
        
        try:
            price = float(price)
            stock = int(stock) if stock else 0
            if price < 0:
                flash('Price cannot be negative.', 'danger')
                return render_template('add_product.html', user=get_user())
        except ValueError:
            flash('Invalid price or stock value.', 'danger')
            return render_template('add_product.html', user=get_user())
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO products (name, description, price, image, stock) VALUES (%s, %s, %s, %s, %s)',
                    (name, description, price, image, stock)
                )
                conn.commit()
                cursor.close()
                flash(f'Product "{name}" added successfully!', 'success')
                return redirect(url_for('home'))
        except Error as e:
            flash('Error adding product. Please try again.', 'danger')
            return render_template('add_product.html', user=get_user())
    
    return render_template('add_product.html', user=get_user())

@app.route('/manage_products')
@admin_required
def manage_products():
    """Manage products (Admin only)"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM products ORDER BY created_at DESC')
            products = cursor.fetchall()
            cursor.close()
        
        return render_template('manage_products.html', products=products, user=get_user())
    except Error as e:
        flash('Error loading products.', 'danger')
        return render_template('manage_products.html', products=[], user=get_user())

@app.route('/delete_product/<int:product_id>')
@admin_required
def delete_product(product_id):
    """Delete product (Admin only)"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if product exists
            cursor.execute('SELECT * FROM products WHERE id = %s', (product_id,))
            product = cursor.fetchone()
            
            if not product:
                flash('Product not found.', 'danger')
                cursor.close()
                return redirect(url_for('manage_products'))
            
            # Remove from carts first
            cursor.execute('DELETE FROM cart WHERE product_id = %s', (product_id,))
            # Delete product
            cursor.execute('DELETE FROM products WHERE id = %s', (product_id,))
            conn.commit()
            cursor.close()
            flash(f'Product "{product["name"]}" deleted successfully!', 'success')
    except Error as e:
        flash('Error deleting product. Please try again.', 'danger')
    
    return redirect(url_for('manage_products'))

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    """Edit existing product (Admin only)"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get the product
            cursor.execute('SELECT * FROM products WHERE id = %s', (product_id,))
            product = cursor.fetchone()
            
            if not product:
                flash('Product not found.', 'danger')
                cursor.close()
                return redirect(url_for('manage_products'))
            
            if request.method == 'POST':
                name = request.form['name'].strip()
                description = request.form['description'].strip()
                price = request.form['price']
                image = request.form['image'].strip()
                stock = request.form.get('stock', 0)
                
                if not name or not price:
                    flash('Name and price are required.', 'danger')
                    cursor.close()
                    return render_template('edit_product.html', product=product, user=get_user())
                
                try:
                    price = float(price)
                    stock = int(stock) if stock else 0
                    if price < 0:
                        flash('Price cannot be negative.', 'danger')
                        cursor.close()
                        return render_template('edit_product.html', product=product, user=get_user())
                except ValueError:
                    flash('Invalid price or stock value.', 'danger')
                    cursor.close()
                    return render_template('edit_product.html', product=product, user=get_user())
                
                cursor.execute(
                    'UPDATE products SET name = %s, description = %s, price = %s, image = %s, stock = %s WHERE id = %s',
                    (name, description, price, image, stock, product_id)
                )
                conn.commit()
                cursor.close()
                flash(f'Product "{name}" updated successfully!', 'success')
                return redirect(url_for('manage_products'))
            
            cursor.close()
    except Error as e:
        flash('Error processing request.', 'danger')
        return redirect(url_for('manage_products'))
    
    return render_template('edit_product.html', product=product, user=get_user())

# ============= ADMIN ORDER MANAGEMENT =============

@app.route('/admin/orders')
@admin_required
def admin_orders():
    """View all orders (Admin only)"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 
                    o.id,
                    o.created_at,
                    o.customer_name,
                    o.customer_phone,
                    o.delivery_address,
                    o.delivery_city,
                    o.delivery_pincode,
                    o.payment_method,
                    o.tracking_number,
                    o.total_amount,
                    o.status,
                    u.username,
                    GROUP_CONCAT(CONCAT(p.name, ' x', oi.quantity) SEPARATOR ', ') as items
                FROM orders o
                JOIN users u ON o.user_id = u.id
                JOIN order_items oi ON o.id = oi.order_id
                JOIN products p ON oi.product_id = p.id
                GROUP BY o.id
                ORDER BY o.created_at DESC
            ''')
            orders = cursor.fetchall()
            cursor.close()
            
        return render_template('admin_orders.html', orders=orders, user=get_user())
    except Error as e:
        print(f"Admin orders error: {e}")
        flash('Error loading orders.', 'danger')
        return render_template('admin_orders.html', orders=[], user=get_user())

@app.route('/admin/order/<int:order_id>/update_status', methods=['POST'])
@admin_required
def update_order_status(order_id):
    """Update order status"""
    new_status = request.form.get('status')
    notes = request.form.get('notes', '')
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Update order status
            cursor.execute(
                'UPDATE orders SET status = %s WHERE id = %s',
                (new_status, order_id)
            )
            
            # Add to status history
            cursor.execute('''
                INSERT INTO order_status_history (order_id, status, notes, updated_by)
                VALUES (%s, %s, %s, %s)
            ''', (order_id, new_status, notes, get_user()['username']))
            
            conn.commit()
            cursor.close()
            
        flash('Order status updated successfully!', 'success')
    except Error as e:
        print(f"Status update error: {e}")
        flash('Error updating order status.', 'danger')
    
    return redirect(url_for('admin_orders'))

@app.route('/admin/order/<int:order_id>')
@admin_required
def admin_order_detail(order_id):
    """View detailed order information"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get order details
            cursor.execute('''
                SELECT o.*, u.username, u.email
                FROM orders o
                JOIN users u ON o.user_id = u.id
                WHERE o.id = %s
            ''', (order_id,))
            order = cursor.fetchone()
            
            if not order:
                flash('Order not found.', 'danger')
                cursor.close()
                return redirect(url_for('admin_orders'))
            
            # Get order items
            cursor.execute('''
                SELECT oi.*, p.name, p.image
                FROM order_items oi
                JOIN products p ON oi.product_id = p.id
                WHERE oi.order_id = %s
            ''', (order_id,))
            items = cursor.fetchall()
            
            # Get status history
            cursor.execute('''
                SELECT * FROM order_status_history
                WHERE order_id = %s
                ORDER BY created_at DESC
            ''', (order_id,))
            history = cursor.fetchall()
            
            cursor.close()
            
        return render_template('admin_order_detail.html', 
                             order=order, 
                             items=items, 
                             history=history,
                             user=get_user())
    except Error as e:
        print(f"Order detail error: {e}")
        flash('Error loading order details.', 'danger')
        return redirect(url_for('admin_orders'))

# ============= ERROR HANDLERS =============

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return render_template('500.html'), 500

# ============= RUN APPLICATION =============

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

