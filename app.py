from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import psycopg2
from psycopg2 import Error
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
import string
from datetime import datetime, timedelta
from contextlib import contextmanager
from functools import wraps
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        env_path = os.path.join(os.getcwd(), '.env')
        if not os.path.exists(env_path):
            return False

        with open(env_path, 'r', encoding='utf-8') as env_file:
            for line in env_file:
                stripped = line.strip()
                if not stripped or stripped.startswith('#') or '=' not in stripped:
                    continue
                key, value = stripped.split('=', 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
        return True

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# Use environment variable for secret key, fallback only for local development
app.secret_key = os.getenv('SECRET_KEY', 'dev-only-secret-key-change-me')

# Site Configuration
SITE_NAME = "Vasundhara Agro Processing unit"
SITE_LOCATION = "Anjangaon Surji"
SITE_TAGLINE = "Pure Ayurvedic Products from Nature"

# Prefer a full URL on Render, with local fallback for development.
DB_URL = os.getenv('DATABASE_URL')
if DB_URL and DB_URL.startswith('postgres://'):
    DB_URL = DB_URL.replace('postgres://', 'postgresql://', 1)
DB_CONFIG = {
    'host': os.getenv('DB_HOST') or os.getenv('PGHOST') or 'localhost',
    'user': os.getenv('DB_USER') or os.getenv('PGUSER') or 'postgres',
    'password': os.getenv('DB_PASSWORD') or os.getenv('PGPASSWORD') or '',
    'dbname': os.getenv('DB_NAME') or os.getenv('PGDATABASE') or 'vasundhara_agro_db',
    'port': int(os.getenv('DB_PORT') or os.getenv('PGPORT') or 5432),
    'sslmode': os.getenv('DB_SSLMODE', 'prefer')
}

# OTP storage (in-memory for development, use Redis in production)
otp_storage = {}

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = None
    try:
        if DB_URL:
            conn = psycopg2.connect(DB_URL, cursor_factory=RealDictCursor)
        else:
            conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        yield conn
    except Error as e:
        print(f"Database connection error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def ensure_column_exists(cursor, table_name, column_name, definition):
    """Add columns when upgrading older database schemas."""
    cursor.execute(
        '''
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s AND column_name = %s
        ''',
        (table_name, column_name)
    )
    if not cursor.fetchone():
        cursor.execute(f'ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}')

def init_db():
    """Initialize the database with tables"""
    # Connect to the database and create tables
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            # Products table
            cursor.execute('''CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                price DECIMAL(10, 2) NOT NULL,
                image VARCHAR(500),
                stock INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            ensure_column_exists(cursor, 'products', 'category_name', 'VARCHAR(100)')
            ensure_column_exists(cursor, 'products', 'is_active', 'BOOLEAN DEFAULT TRUE')
            
            # Cart table
            cursor.execute('''CREATE TABLE IF NOT EXISTS cart (
                id SERIAL PRIMARY KEY,
                user_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE
            )''')
            
            # Orders table with delivery tracking
            cursor.execute('''CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY,
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
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )''')
            
            # Order items table
            cursor.execute('''CREATE TABLE IF NOT EXISTS order_items (
                id SERIAL PRIMARY KEY,
                order_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL,
                price DECIMAL(10, 2) NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE
            )''')
            
            # Order status history table
            cursor.execute('''CREATE TABLE IF NOT EXISTS order_status_history (
                id SERIAL PRIMARY KEY,
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
                    ('admin', admin_password, 'admin@example.com', True)
                )
                conn.commit()
                print("Admin user created: username='admin', password='admin123'")
            
            # Fix NULL customer names in existing orders
            cursor.execute('''
                UPDATE orders o
                SET customer_name = u.username
                FROM users u
                WHERE o.user_id = u.id AND o.customer_name IS NULL
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
    print(f"?? SMS to {phone}:")
    print(f"   {message}")
    print(f"{'='*60}\n")
    # Production code would call actual SMS API here
    return True

def normalize_category_name(category_name):
    """Normalize product category text for consistent filtering."""
    cleaned = ' '.join((category_name or '').split())
    return cleaned.title() if cleaned else None

def parse_price_filter(raw_value):
    """Parse price filters without failing on bad query strings."""
    if raw_value in (None, ''):
        return None
    try:
        value = float(raw_value)
        return value if value >= 0 else None
    except (TypeError, ValueError):
        return None

def build_product_view(product):
    """Convert a DB row into a richer template-friendly product object."""
    description = (product.get('description') or '').strip()
    stock = max(int(product.get('stock') or 0), 0)
    price = float(product.get('price') or 0)
    category_name = normalize_category_name(product.get('category_name')) or 'General Collection'

    if stock <= 0:
        stock_label = 'Out of stock'
        stock_tone = 'danger'
    elif stock <= 5:
        stock_label = f'Only {stock} left'
        stock_tone = 'warning'
    else:
        stock_label = 'Ready to ship'
        stock_tone = 'success'

    short_description = description
    if len(short_description) > 120:
        short_description = short_description[:117].rstrip() + '...'

    return {
        'id': product.get('id') or product.get('product_id'),
        'name': product['name'],
        'description': description,
        'short_description': short_description,
        'price': price,
        'image': product.get('image'),
        'stock': stock,
        'category_name': category_name,
        'is_active': bool(product.get('is_active', 1)),
        'created_at': product.get('created_at'),
        'in_stock': stock > 0,
        'low_stock': 0 < stock <= 5,
        'stock_label': stock_label,
        'stock_tone': stock_tone,
    }

def build_cart_item_view(item):
    """Decorate cart rows with pricing and stock validation metadata."""
    product = build_product_view(item)
    quantity = int(item.get('quantity') or 0)
    subtotal = product['price'] * quantity
    stock_message = ''
    stock_issue = False

    if product['stock'] <= 0:
        stock_issue = True
        stock_message = 'This product is currently unavailable.'
    elif quantity > product['stock']:
        stock_issue = True
        stock_message = f'Only {product["stock"]} available right now. Please reduce quantity.'
    elif product['low_stock']:
        stock_message = f'Fast moving item. Only {product["stock"]} left in stock.'

    return {
        **product,
        'cart_id': item.get('id'),
        'quantity': quantity,
        'subtotal': subtotal,
        'stock_issue': stock_issue,
        'stock_message': stock_message,
    }

def fetch_distinct_categories(cursor):
    """List available categories for storefront filters."""
    cursor.execute(
        '''
        SELECT DISTINCT category_name
        FROM products
        WHERE is_active = TRUE
          AND category_name IS NOT NULL
          AND TRIM(category_name) <> ''
        ORDER BY category_name ASC
        '''
    )
    return [row['category_name'] for row in cursor.fetchall()]

def fetch_cart_items(cursor, user_id):
    """Load cart items together with their products."""
    cursor.execute(
        '''
        SELECT
            c.id,
            c.quantity,
            p.id AS product_id,
            p.name,
            p.description,
            p.price,
            p.image,
            p.stock,
            p.category_name,
            p.created_at
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = %s
        ORDER BY c.created_at DESC
        ''',
        (user_id,)
    )
    raw_items = cursor.fetchall()
    items = [build_cart_item_view(item) for item in raw_items]
    summary = {
        'total': sum(item['subtotal'] for item in items),
        'item_count': sum(item['quantity'] for item in items),
        'has_stock_issues': any(item['stock_issue'] for item in items),
    }
    return items, summary

def get_cart_count_for_user(user_id):
    """Return the total quantity of items in a user's cart."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT COALESCE(SUM(quantity), 0) AS total_items FROM cart WHERE user_id = %s',
                (user_id,)
            )
            result = cursor.fetchone()
            cursor.close()
        return int((result or {}).get('total_items') or 0)
    except Error:
        return 0

def get_safe_redirect(default_endpoint='cart'):
    """Allow only local next paths from forms."""
    next_path = request.form.get('next', '').strip()
    if next_path.startswith('/'):
        return next_path
    return url_for(default_endpoint)

@app.context_processor
def inject_site_context():
    """Provide shared branding and cart data to templates."""
    user = get_user()
    cart_count = get_cart_count_for_user(user['id']) if user else 0
    return {
        'site_name': SITE_NAME,
        'site_location': SITE_LOCATION,
        'site_tagline': SITE_TAGLINE,
        'current_user': user,
        'cart_count': cart_count,
        'current_year': datetime.now().year,
    }

def login_required(f):
    """Decorator for routes that require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not get_user():
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator for routes that require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_user()
        if not user or not user.get('is_admin'):
            flash('Admin access required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# ============= PUBLIC ROUTES =============

@app.route('/')
def home():
    """Home page with product listing, filters, and sorting."""
    search_query = request.args.get('search', '').strip()
    selected_category = normalize_category_name(request.args.get('category', ''))
    sort_option = request.args.get('sort', 'newest')
    min_price = parse_price_filter(request.args.get('min_price'))
    max_price = parse_price_filter(request.args.get('max_price'))
    sort_map = {
        'newest': 'created_at DESC',
        'price_low': 'price ASC, created_at DESC',
        'price_high': 'price DESC, created_at DESC',
        'name_az': 'name ASC',
        'name_za': 'name DESC',
    }

    if sort_option not in sort_map:
        sort_option = 'newest'
    if min_price is not None and max_price is not None and min_price > max_price:
        min_price, max_price = max_price, min_price

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            filters = ['is_active = TRUE']
            params = []
            if search_query:
                like_value = f'%{search_query}%'
                filters.append('(name ILIKE %s OR description ILIKE %s)')
                params.extend([like_value, like_value])
            if selected_category:
                filters.append('category_name = %s')
                params.append(selected_category)
            if min_price is not None:
                filters.append('price >= %s')
                params.append(min_price)
            if max_price is not None:
                filters.append('price <= %s')
                params.append(max_price)

            where_clause = f"WHERE {' AND '.join(filters)}" if filters else ''
            cursor.execute(
                f'''
                SELECT id, name, description, price, image, stock, category_name, created_at
                FROM products
                {where_clause}
                ORDER BY {sort_map[sort_option]}
                ''',
                params
            )
            products = [build_product_view(product) for product in cursor.fetchall()]

            categories = fetch_distinct_categories(cursor)
            cursor.execute(
                '''
                SELECT
                    COUNT(*) AS total_products,
                    COALESCE(SUM(CASE WHEN stock > 0 THEN 1 ELSE 0 END), 0) AS available_products,
                    COALESCE(COUNT(DISTINCT CASE
                        WHEN category_name IS NULL OR TRIM(category_name) = '' THEN NULL
                        ELSE category_name
                    END), 0) AS category_count
                FROM products
                WHERE is_active = TRUE
                '''
            )
            store_stats = cursor.fetchone() or {}
            cursor.close()

        return render_template(
            'home.html',
            products=products,
            categories=categories,
            search_query=search_query,
            selected_category=selected_category or '',
            min_price='' if min_price is None else min_price,
            max_price='' if max_price is None else max_price,
            sort_option=sort_option,
            result_count=len(products),
            active_filters=bool(search_query or selected_category or min_price is not None or max_price is not None),
            store_stats={
                'total_products': int(store_stats.get('total_products') or 0),
                'available_products': int(store_stats.get('available_products') or 0),
                'category_count': int(store_stats.get('category_count') or 0),
            },
            user=get_user(),
        )
    except Error as e:
        flash('Error loading products.', 'danger')
        return render_template(
            'home.html',
            products=[],
            categories=[],
            search_query=search_query,
            selected_category=selected_category or '',
            min_price='' if min_price is None else min_price,
            max_price='' if max_price is None else max_price,
            sort_option=sort_option,
            result_count=0,
            active_filters=bool(search_query or selected_category or min_price is not None or max_price is not None),
            store_stats={'total_products': 0, 'available_products': 0, 'category_count': 0},
            user=get_user(),
        )

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
            cursor.execute(
                '''
                SELECT id, name, description, price, image, stock, category_name, is_active, created_at
                FROM products
                WHERE id = %s AND is_active = TRUE
                ''',
                (product_id,)
            )
            product = cursor.fetchone()

            if not product:
                cursor.close()
                flash('Product not found.', 'danger')
                return redirect(url_for('home'))

            product_view = build_product_view(product)
            min_related_price = max(product_view['price'] - 300, 0)
            max_related_price = product_view['price'] + 300

            cursor.execute(
                '''
                SELECT id, name, description, price, image, stock, category_name, is_active, created_at
                FROM products
                    WHERE is_active = TRUE
                  AND id <> %s
                  AND (
                        category_name = %s
                        OR price BETWEEN %s AND %s
                      )
                ORDER BY
                    CASE WHEN category_name = %s THEN 0 ELSE 1 END,
                    created_at DESC
                LIMIT 4
                ''',
                (
                    product_id,
                    product.get('category_name'),
                    min_related_price,
                    max_related_price,
                    product.get('category_name'),
                )
            )
            related_products = [build_product_view(item) for item in cursor.fetchall()]

            if not related_products:
                cursor.execute(
                    '''
                    SELECT id, name, description, price, image, stock, category_name, is_active, created_at
                    FROM products
                    WHERE is_active = TRUE AND id <> %s
                    ORDER BY created_at DESC
                    LIMIT 4
                    ''',
                    (product_id,)
                )
                related_products = [build_product_view(item) for item in cursor.fetchall()]

            cursor.close()

        return render_template(
            'product_detail.html',
            product=product_view,
            related_products=related_products,
            user=get_user(),
        )
    except Error as e:
        flash('Error loading product.', 'danger')
        return redirect(url_for('home'))

# ============= CART ROUTES =============

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    """Add product to cart"""
    redirect_target = get_safe_redirect()

    try:
        quantity = int(request.form.get('quantity', 1))
        if quantity <= 0:
            flash('Invalid quantity.', 'danger')
            return redirect(redirect_target)
    except ValueError:
        flash('Invalid quantity.', 'danger')
        return redirect(redirect_target)
    
    user = get_user()
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if product exists
            cursor.execute('SELECT * FROM products WHERE id = %s AND is_active = TRUE', (product_id,))
            product = cursor.fetchone()
            
            if not product:
                flash('Product not found.', 'danger')
                cursor.close()
                return redirect(url_for('home'))

            available_stock = max(int(product.get('stock') or 0), 0)
            if available_stock <= 0:
                flash(f'{product["name"]} is currently out of stock.', 'warning')
                cursor.close()
                return redirect(redirect_target)
            if quantity > available_stock:
                flash(f'Only {available_stock} unit(s) of {product["name"]} are available.', 'warning')
                cursor.close()
                return redirect(redirect_target)
            
            # Check if item is already in cart
            cursor.execute(
                'SELECT * FROM cart WHERE user_id = %s AND product_id = %s', 
                (user['id'], product_id)
            )
            existing_item = cursor.fetchone()
            
            if existing_item:
                # Update quantity
                new_quantity = existing_item['quantity'] + quantity
                if new_quantity > available_stock:
                    flash(
                        f'You already have {existing_item["quantity"]} in cart. '
                        f'Only {available_stock} unit(s) are available.',
                        'warning'
                    )
                    cursor.close()
                    return redirect(redirect_target)
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
    
    return redirect(redirect_target)

@app.route('/cart')
@login_required
def cart():
    """Shopping cart page"""
    user = get_user()
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cart_items, summary = fetch_cart_items(cursor, user['id'])
            cursor.close()

        return render_template('cart.html', items=cart_items, summary=summary, user=user)
    except Error as e:
        flash('Error loading cart.', 'danger')
        return render_template(
            'cart.html',
            items=[],
            summary={'total': 0, 'item_count': 0, 'has_stock_issues': False},
            user=user,
        )

@app.route('/cart/update/<int:cart_id>', methods=['POST'])
@login_required
def update_cart(cart_id):
    """Update cart quantity with stock validation."""
    user = get_user()

    try:
        quantity = int(request.form.get('quantity', 1))
    except ValueError:
        flash('Please enter a valid quantity.', 'danger')
        return redirect(url_for('cart'))

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT c.id, c.quantity, p.name, p.stock
                FROM cart c
                JOIN products p ON c.product_id = p.id
                WHERE c.id = %s AND c.user_id = %s
                ''',
                (cart_id, user['id'])
            )
            cart_item = cursor.fetchone()

            if not cart_item:
                flash('Cart item not found.', 'danger')
                cursor.close()
                return redirect(url_for('cart'))

            available_stock = max(int(cart_item.get('stock') or 0), 0)
            if quantity <= 0:
                cursor.execute('DELETE FROM cart WHERE id = %s AND user_id = %s', (cart_id, user['id']))
                conn.commit()
                cursor.close()
                flash('Item removed from cart.', 'info')
                return redirect(url_for('cart'))

            if available_stock <= 0:
                flash(f'{cart_item["name"]} is out of stock. Remove it to continue.', 'warning')
                cursor.close()
                return redirect(url_for('cart'))

            if quantity > available_stock:
                flash(f'Only {available_stock} unit(s) of {cart_item["name"]} are available.', 'warning')
                cursor.close()
                return redirect(url_for('cart'))

            cursor.execute(
                'UPDATE cart SET quantity = %s WHERE id = %s AND user_id = %s',
                (quantity, cart_id, user['id'])
            )
            conn.commit()
            cursor.close()
            flash(f'Updated {cart_item["name"]} quantity.', 'success')
    except Error:
        flash('Unable to update your cart right now.', 'danger')

    return redirect(url_for('cart'))

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
            cart_items, summary = fetch_cart_items(cursor, user['id'])
            cursor.close()

            if not cart_items:
                flash('Your cart is empty.', 'warning')
                return redirect(url_for('cart'))

            if summary['has_stock_issues']:
                flash('Please fix cart stock issues before checkout.', 'warning')
                return redirect(url_for('cart'))

            return render_template(
                'checkout_with_otp.html',
                cart_items=cart_items,
                summary=summary,
                user=user,
            )
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
    if send_otp_sms(phone, f"Your VAPU OTP is {otp}. Valid for 5 minutes."):
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
                SELECT c.quantity, p.id as product_id, p.name, p.price, p.stock
                FROM cart c
                JOIN products p ON c.product_id = p.id
                WHERE c.user_id = %s
            ''', (user['id'],))
            cart_items = cursor.fetchall()
            
            if not cart_items:
                flash('Your cart is empty.', 'warning')
                cursor.close()
                return redirect(url_for('cart'))
            
            unavailable_items = [
                item['name']
                for item in cart_items
                if int(item.get('stock') or 0) < int(item.get('quantity') or 0)
            ]
            if unavailable_items:
                cursor.close()
                flash(
                    'Some items changed while you were shopping. Please review your cart before checkout.',
                    'warning'
                )
                return redirect(url_for('cart'))

            total_amount = sum(float(item['price']) * item['quantity'] for item in cart_items)
            
            # Generate tracking number
            tracking_number = 'VAPU' + ''.join(random.choices(string.digits, k=8))
            
            # Create order with delivery details
            cursor.execute('''
                INSERT INTO orders 
                (user_id, customer_name, customer_phone, delivery_address, 
                 delivery_city, delivery_pincode, delivery_instructions, 
                 payment_method, tracking_number, total_amount, status) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (user['id'], customer_name, customer_phone, delivery_address,
                  delivery_city, delivery_pincode, delivery_instructions,
                  payment_method, tracking_number, total_amount, 'confirmed'))
            
            order_row = cursor.fetchone() or {}
            order_id = order_row.get('id')
            
            # Add order items
            for item in cart_items:
                cursor.execute('''
                    INSERT INTO order_items (order_id, product_id, quantity, price) 
                    VALUES (%s, %s, %s, %s)
                ''', (order_id, item['product_id'], item['quantity'], float(item['price'])))

                cursor.execute(
                    '''
                    UPDATE products
                    SET stock = stock - %s
                    WHERE id = %s AND stock >= %s
                    ''',
                    (item['quantity'], item['product_id'], item['quantity'])
                )

                if cursor.rowcount != 1:
                    conn.rollback()
                    cursor.close()
                    flash(
                        f'{item["name"]} is no longer available in the requested quantity. Please review your cart.',
                        'warning'
                    )
                    return redirect(url_for('cart'))
            
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
                        f"Order confirmed! Tracking: {tracking_number}. Total: ?{total_amount:.2f}")
            
            flash(f'Order placed successfully! Tracking: {tracking_number}', 'success')
            return render_template(
                'checkout.html',
                user=user,
                order={
                    'id': order_id,
                    'tracking_number': tracking_number,
                    'total_amount': total_amount,
                    'payment_method': payment_method,
                    'customer_name': customer_name,
                },
            )
            
    except Error as e:
        print(f"Checkout error: {e}")
        flash('Error processing order. Please try again.', 'danger')
        return redirect(url_for('cart'))

# ============= ORDER ROUTES =============

@app.route('/orders')
@login_required
def orders():
    """User order dashboard with history and quick stats."""
    user = get_user()
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT
                    o.id,
                    o.total_amount,
                    o.status,
                    o.created_at,
                    o.tracking_number,
                    o.payment_method,
                    o.delivery_city,
                    o.delivery_pincode,
                    o.customer_name,
                    COALESCE(SUM(oi.quantity), 0) AS total_items,
                    STRING_AGG(p.name || ' (x' || oi.quantity::text || ')', ', ' ORDER BY p.name) AS items
                FROM orders o
                LEFT JOIN order_items oi ON o.id = oi.order_id
                LEFT JOIN products p ON oi.product_id = p.id
                WHERE o.user_id = %s
                GROUP BY o.id
                ORDER BY o.created_at DESC
            ''', (user['id'],))
            user_orders = cursor.fetchall()

            cursor.execute(
                '''
                SELECT
                    COUNT(*) AS total_orders,
                    COALESCE(SUM(total_amount), 0) AS total_spent,
                    COALESCE(SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END), 0) AS delivered_orders,
                    COALESCE(SUM(CASE
                        WHEN status IN ('pending', 'confirmed', 'processing', 'packed', 'shipped', 'out_for_delivery')
                        THEN 1 ELSE 0
                    END), 0) AS active_orders
                FROM orders
                WHERE user_id = %s
                ''',
                (user['id'],)
            )
            order_stats = cursor.fetchone() or {}
            cursor.close()

        orders_list = []
        for order in user_orders:
            orders_list.append(
                {
                    'id': order['id'],
                    'items': order['items'] or 'No items',
                    'total_amount': float(order['total_amount']),
                    'status': order['status'],
                    'created_at': order['created_at'],
                    'tracking_number': order['tracking_number'],
                    'payment_method': order.get('payment_method') or 'COD',
                    'delivery_city': order.get('delivery_city') or 'Unknown city',
                    'delivery_pincode': order.get('delivery_pincode') or '-',
                    'customer_name': order.get('customer_name') or user['username'],
                    'total_items': int(order.get('total_items') or 0),
                }
            )

        return render_template(
            'orders.html',
            orders=orders_list,
            order_stats={
                'total_orders': int(order_stats.get('total_orders') or 0),
                'total_spent': float(order_stats.get('total_spent') or 0),
                'delivered_orders': int(order_stats.get('delivered_orders') or 0),
                'active_orders': int(order_stats.get('active_orders') or 0),
            },
            user=user,
        )
    except Error as e:
        flash('Error loading orders.', 'danger')
        return render_template(
            'orders.html',
            orders=[],
            order_stats={'total_orders': 0, 'total_spent': 0, 'delivered_orders': 0, 'active_orders': 0},
            user=user,
        )

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
                      STRING_AGG(p.name || ' x' || oi.quantity::text, ', ' ORDER BY p.name) as items
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
        image = request.form.get('image', '').strip() or None
        stock = request.form.get('stock', 0)
        category_name = normalize_category_name(request.form.get('category_name', ''))
        
        if not name or not price:
            flash('Name and price are required.', 'danger')
            return render_template('add_product.html', user=get_user())
        
        try:
            price = float(price)
            stock = int(stock) if stock else 0
            if price < 0:
                flash('Price cannot be negative.', 'danger')
                return render_template('add_product.html', user=get_user())
            if stock < 0:
                flash('Stock cannot be negative.', 'danger')
                return render_template('add_product.html', user=get_user())
        except ValueError:
            flash('Invalid price or stock value.', 'danger')
            return render_template('add_product.html', user=get_user())
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    '''
                    INSERT INTO products (name, description, price, image, stock, category_name, is_active)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ''',
                    (name, description, price, image, stock, category_name, True)
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
            cursor.execute(
                '''
                SELECT id, name, description, price, image, stock, category_name, is_active, created_at
                FROM products
                WHERE is_active = TRUE
                ORDER BY created_at DESC
                '''
            )
            products = [build_product_view(product) for product in cursor.fetchall()]
            cursor.close()

        return render_template(
            'manage_products.html',
            products=products,
            product_stats={
                'total_products': len(products),
                'low_stock_products': sum(1 for product in products if product['low_stock']),
                'out_of_stock_products': sum(1 for product in products if not product['in_stock']),
            },
            user=get_user(),
        )
    except Error as e:
        flash('Error loading products.', 'danger')
        return render_template(
            'manage_products.html',
            products=[],
            product_stats={'total_products': 0, 'low_stock_products': 0, 'out_of_stock_products': 0},
            user=get_user(),
        )

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
                image = request.form.get('image', '').strip() or None
                stock = request.form.get('stock', 0)
                category_name = normalize_category_name(request.form.get('category_name', ''))
                
                if not name or not price:
                    flash('Name and price are required.', 'danger')
                    cursor.close()
                    return render_template(
                        'edit_product.html',
                        product={**product, 'name': name, 'description': description, 'image': image, 'category_name': category_name},
                        user=get_user(),
                    )
                
                try:
                    price = float(price)
                    stock = int(stock) if stock else 0
                    if price < 0:
                        flash('Price cannot be negative.', 'danger')
                        cursor.close()
                        return render_template(
                            'edit_product.html',
                            product={**product, 'name': name, 'description': description, 'price': price, 'image': image, 'stock': stock, 'category_name': category_name},
                            user=get_user(),
                        )
                    if stock < 0:
                        flash('Stock cannot be negative.', 'danger')
                        cursor.close()
                        return render_template(
                            'edit_product.html',
                            product={**product, 'name': name, 'description': description, 'price': price, 'image': image, 'stock': stock, 'category_name': category_name},
                            user=get_user(),
                        )
                except ValueError:
                    flash('Invalid price or stock value.', 'danger')
                    cursor.close()
                    return render_template(
                        'edit_product.html',
                        product={**product, 'name': name, 'description': description, 'image': image, 'stock': stock, 'category_name': category_name},
                        user=get_user(),
                    )
                
                cursor.execute(
                    '''
                    UPDATE products
                    SET name = %s, description = %s, price = %s, image = %s, stock = %s, category_name = %s
                    WHERE id = %s
                    ''',
                    (name, description, price, image, stock, category_name, product_id)
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
                    STRING_AGG(p.name || ' x' || oi.quantity::text, ', ' ORDER BY p.name) as items
                FROM orders o
                JOIN users u ON o.user_id = u.id
                JOIN order_items oi ON o.id = oi.order_id
                JOIN products p ON oi.product_id = p.id
                GROUP BY o.id, u.username
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
                'UPDATE orders SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s',
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
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))  # Use platform port
    app.run(host='0.0.0.0', port=port)
