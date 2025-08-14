from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, make_response
import sqlite3
import json
import hashlib
import os
from datetime import datetime, timedelta
import secrets
import random
import re
from html import escape
import requests
import uuid
import emotion_api

app = Flask(__name__)

# Input validation and sanitization functions
def validate_email(email):
    """Validate email format and sanitize input"""
    if not email or len(email) > 254:
        return False
    
    # Sanitize input
    email = escape(email.strip().lower())
    
    # Regex pattern for email validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email) is not None

def validate_password(password):
    """Validate password strength with detailed feedback"""
    errors = []
    
    if not password:
        errors.append("Password is required")
        return errors
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if len(password) > 128:
        errors.append("Password cannot exceed 128 characters")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter (A-Z)")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter (a-z)")
    
    if not re.search(r'[0-9]', password):
        errors.append("Password must contain at least one number (0-9)")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character (!@#$%^&*)")
    
    return errors

def validate_name(name):
    """Validate and sanitize name input"""
    if not name or len(name) > 50:
        return False
    
    # Sanitize and check for valid characters (letters, spaces, hyphens, apostrophes)
    name = escape(name.strip())
    name_pattern = r"^[a-zA-Z\s\-']{1,50}$"
    return re.match(name_pattern, name) is not None

def validate_teddy_code(code):
    """Validate TEDDY device code"""
    if not code:
        return False
    
    # Must be exactly 6 digits
    code = str(code).strip()
    return re.match(r'^\d{6}$', code) is not None

def validate_date(date_str):
    """Validate date format (YYYY-MM-DD)"""
    if not date_str:
        return False
    
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def sanitize_input(input_str, max_length=None):
    """General input sanitization"""
    if not input_str:
        return ""
    
    # Remove any potentially dangerous characters and escape HTML
    sanitized = escape(str(input_str).strip())
    
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized

def validate_user_input(data, required_fields, validation_rules):
    """Centralized input validation"""
    errors = []
    
    # Check required fields
    for field in required_fields:
        if field not in data or not data[field]:
            errors.append(f"{field.replace('_', ' ').title()} is required")
    
    # Apply validation rules
    for field, validator in validation_rules.items():
        if field in data and data[field]:
            if not validator(data[field]):
                errors.append(f"Invalid {field.replace('_', ' ')}")
    
    return errors

def generate_csrf_token():
    """Generate a CSRF token for forms"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    return token and session.get('csrf_token') == token

def verify_turnstile(token):
    """Verify Turnstile CAPTCHA token"""
    # Check if Turnstile is enabled in config
    turnstile_config = config.get('turnstile', {})
    if not turnstile_config.get('enabled', True):
        print("Turnstile is disabled in config - skipping verification")
        return True
    
    if not token:
        return False
    
    secret_key = turnstile_config.get('secret_key', '')
    
    if not secret_key:
        print("Turnstile secret key not configured")
        return False
    
    try:
        response = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={
                'secret': secret_key,
                'response': token,
                'remoteip': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            },
            timeout=10
        )
        
        result = response.json()
        return result.get('success', False)
    
    except Exception as e:
        # Log the error in production
        print(f"Turnstile verification error: {e}")
        return False

# Make CSRF token, config, and helper functions available to all templates
@app.context_processor
def inject_csrf_token():
    return dict(
        csrf_token=generate_csrf_token(), 
        config=config,
        is_admin=is_admin,
        get_user_dashboard_url=get_user_dashboard_url,
        get_user_dashboard_endpoint=get_user_dashboard_endpoint
    )

# Template filters for date formatting
@app.template_filter('format_date')
def format_date(date_string, format_type='short'):
    """Format date strings for display"""
    if not date_string:
        return 'Never'
    
    try:
        from datetime import datetime
        # Parse the date string
        if isinstance(date_string, str):
            # Try different formats
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%Y-%m-%d %H:%M:%S.%f']:
                try:
                    date_obj = datetime.strptime(date_string, fmt)
                    break
                except ValueError:
                    continue
            else:
                return date_string  # Return original if can't parse
        else:
            date_obj = date_string
            
        if format_type == 'short':
            return date_obj.strftime('%b %d, %Y')
        elif format_type == 'long':
            return date_obj.strftime('%B %d, %Y at %I:%M %p')
        else:
            return date_obj.strftime(format_type)
    except:
        return date_string

@app.template_filter('time_ago')
def time_ago(date_string):
    """Format date as time ago (e.g., '2 days ago')"""
    if not date_string:
        return 'Never'
    
    try:
        from datetime import datetime
        if isinstance(date_string, str):
            # Try different formats
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%Y-%m-%d %H:%M:%S.%f']:
                try:
                    date_obj = datetime.strptime(date_string, fmt)
                    break
                except ValueError:
                    continue
            else:
                return date_string
        else:
            date_obj = date_string
            
        now = datetime.now()
        diff = now - date_obj
        
        if diff.days > 365:
            years = diff.days // 365
            return f"{years} year{'s' if years != 1 else ''} ago"
        elif diff.days > 30:
            months = diff.days // 30
            return f"{months} month{'s' if months != 1 else ''} ago"
        elif diff.days > 0:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"
    except:
        return date_string

# Simple rate limiting
login_attempts = {}

def check_rate_limit(ip_address, max_attempts=5, window_minutes=15):
    """Check if IP address has exceeded login attempt limit"""
    current_time = datetime.now()
    
    if ip_address not in login_attempts:
        login_attempts[ip_address] = []
    
    # Remove old attempts outside the window
    cutoff_time = current_time - timedelta(minutes=window_minutes)
    login_attempts[ip_address] = [
        attempt for attempt in login_attempts[ip_address] 
        if attempt > cutoff_time
    ]
    
    # Check if limit exceeded
    if len(login_attempts[ip_address]) >= max_attempts:
        return False
    
    return True

def record_login_attempt(ip_address):
    """Record a failed login attempt"""
    if ip_address not in login_attempts:
        login_attempts[ip_address] = []
    
    login_attempts[ip_address].append(datetime.now())

# Load configuration
def load_config():
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Create default config if it doesn't exist
        default_config = {
            "secret_key": secrets.token_hex(16),
            "database_path": "teddy.db",
            "api_key": secrets.token_hex(32),
            "website_url": "your-domain.com",
            "manager_name": "Your Name",
            "manager_url": "your-manager-site.com",
            "turnstile": {
                "enabled": True,
                "site_key": "",
                "secret_key": ""
            }
        }
        with open('config.json', 'w') as f:
            json.dump(default_config, f, indent=4)
        return default_config

config = load_config()
app.secret_key = config['secret_key']

# Store config in app context for emotion API
app.config['TEDDY_CONFIG'] = config

# Import and register emotion API blueprint
try:
    from emotion_api import emotion_bp
    app.register_blueprint(emotion_bp)
    print("✓ Emotion API integrated successfully")
except ImportError as e:
    print(f"⚠ Warning: Could not import emotion API: {e}")
except Exception as e:
    print(f"⚠ Warning: Error registering emotion API: {e}")

@app.before_request
def check_remember_token():
    """Check for remember token if user is not logged in"""
    # Skip remember token check for auth routes and static files
    if (request.endpoint and 
        (request.endpoint == 'static' or
         request.endpoint in ['login_page', 'register_page', 'landing_page', 'login', 'register'])):
        return
    
    # If user is not logged in, check for remember token
    if 'user_id' not in session:
        remember_token = request.cookies.get('remember_token')
        if remember_token:
            user = get_user_by_remember_token(remember_token)
            if user:
                session['user_id'] = user['id']
            else:
                # Invalid or expired token, remove cookie
                response = make_response()
                response.set_cookie('remember_token', '', expires=0)
                return response
    
    # Clean up expired tokens periodically (1% chance per request)
    if random.randint(1, 100) == 1:
        cleanup_expired_tokens()

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(config['database_path'])
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            birthday TEXT,
            country TEXT,
            contact_number TEXT,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Add is_admin column if it doesn't exist (for existing databases)
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Teddy devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS teddy_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teddy_code TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            battery_level INTEGER DEFAULT 0,
            target_user TEXT DEFAULT 'Children',
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Teddy data logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS teddy_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teddy_code TEXT NOT NULL,
            battery_level INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (teddy_code) REFERENCES teddy_devices (teddy_code)
        )
    ''')
    
    # Remember tokens table for "Remember Me" functionality
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS remember_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # Emotion analysis results table for ESP32 data
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS emotion_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teddy_code TEXT NOT NULL,
            emotion TEXT NOT NULL,
            confidence REAL,
            data_type TEXT NOT NULL,
            transcript TEXT,
            matches TEXT,
            all_candidates TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (teddy_code) REFERENCES teddy_devices (teddy_code)
        )
    ''')
    
    conn.commit()
    conn.close()

def create_admin_user():
    """Create initial admin user if none exists"""
    conn = get_db_connection()
    
    # Check if any admin users exist
    admin_count = conn.execute('SELECT COUNT(*) FROM users WHERE is_admin = 1').fetchone()[0]
    
    if admin_count == 0:
        # Create default admin user
        admin_email = 'admin@teddy.com'
        admin_password = '@Test123#'  # Change this immediately after first login
        
        # Check if this email already exists
        existing_user = conn.execute('SELECT id FROM users WHERE email = ?', (admin_email,)).fetchone()
        
        if existing_user:
            # Make existing user an admin
            conn.execute('UPDATE users SET is_admin = 1 WHERE email = ?', (admin_email,))
            print(f"Made existing user {admin_email} an admin")
        else:
            # Create new admin user
            password_hash = hashlib.sha256(admin_password.encode()).hexdigest()
            conn.execute('''
                INSERT INTO users (email, password_hash, first_name, last_name, is_admin)
                VALUES (?, ?, ?, ?, ?)
            ''', (admin_email, password_hash, 'Admin', 'User', 1))
            print(f"Created admin user: {admin_email} with password: {admin_password}")
            print("Please change the admin password immediately after first login!")
    
    conn.commit()
    conn.close()

def hash_password(password):
    """Hash password with SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(config['database_path'])
    conn.row_factory = sqlite3.Row
    return conn

def get_user_dashboard_endpoint(user_id):
    """Get the appropriate dashboard endpoint name for a user based on their role"""
    if is_admin(user_id):
        return 'admin_dashboard'
    else:
        return 'user_dashboard'

def get_user_dashboard_url(user_id):
    """Get the appropriate dashboard URL for a user based on their role"""
    if is_admin(user_id):
        return url_for('admin_dashboard')
    else:
        return url_for('user_dashboard')

def is_admin(user_id):
    """Check if user is an admin"""
    if not user_id:
        return False
    
    conn = get_db_connection()
    user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    return user and user['is_admin'] == 1

def require_admin(f):
    """Decorator to require admin access"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login_page'))
        
        if not is_admin(session['user_id']):
            flash('Admin access required.', 'error')
            return redirect(url_for('user_dashboard'))
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def create_remember_token(user_id):
    """Create a remember token for the user"""
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(days=7)).isoformat()
    
    conn = get_db_connection()
    # Clean up old tokens for this user
    conn.execute('DELETE FROM remember_tokens WHERE user_id = ?', (user_id,))
    # Insert new token
    conn.execute('INSERT INTO remember_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
                (user_id, token, expires_at))
    conn.commit()
    conn.close()
    
    return token

def get_user_by_remember_token(token):
    """Get user by remember token if valid"""
    conn = get_db_connection()
    result = conn.execute('''
        SELECT u.*, rt.token FROM users u 
        JOIN remember_tokens rt ON u.id = rt.user_id 
        WHERE rt.token = ? AND rt.expires_at > ?
    ''', (token, datetime.now().isoformat())).fetchone()
    conn.close()
    
    return result

def delete_remember_token(token):
    """Delete a remember token"""
    conn = get_db_connection()
    conn.execute('DELETE FROM remember_tokens WHERE token = ?', (token,))
    conn.commit()
    conn.close()

def cleanup_expired_tokens():
    """Remove expired remember tokens"""
    conn = get_db_connection()
    conn.execute('DELETE FROM remember_tokens WHERE expires_at < ?', (datetime.now().isoformat(),))
    conn.commit()
    conn.close()

def validate_api_key():
    """Validate API key from request headers"""
    api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization')
    if api_key and api_key.startswith('Bearer '):
        api_key = api_key[7:]  # Remove 'Bearer ' prefix
    
    return api_key == config['api_key']

@app.route('/')
def landing_page():
    """Landing page for Project TEDDY"""
    return render_template('landing.html', config=config)

@app.route('/login')
def login_page():
    """Login page"""
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        try:
            return redirect(url_for(get_user_dashboard_endpoint(session['user_id'])))
        except Exception as e:
            # If there's an issue with the user, clear session and continue to login
            session.clear()
            app.logger.error(f"Error redirecting logged in user: {e}")
    return render_template('login.html')

@app.route('/register')
def register_page():
    """Registration page"""
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        try:
            return redirect(url_for(get_user_dashboard_endpoint(session['user_id'])))
        except Exception as e:
            # If there's an issue with the user, clear session and continue to registration
            session.clear()
            app.logger.error(f"Error redirecting logged in user: {e}")
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """Main dashboard - redirects to appropriate dashboard based on user role"""
    if 'user_id' not in session:
        flash('Please login to access the dashboard.', 'error')
        return redirect(url_for('login_page'))
    
    # Redirect to appropriate dashboard based on user role
    return redirect(get_user_dashboard_url(session['user_id']))

@app.route('/user-dashboard')
def user_dashboard():
    """User dashboard page - for regular users only"""
    if 'user_id' not in session:
        flash('Please login to access the dashboard.', 'error')
        return redirect(url_for('login_page'))
    
    # Prevent admins from accessing user dashboard
    if is_admin(session['user_id']):
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    teddy = conn.execute('SELECT * FROM teddy_devices WHERE user_id = ?', (session['user_id'],)).fetchone()
    conn.close()

    return render_template('dashboard.html', user=user, teddy=teddy)

@app.route('/emotion-analysis')
def emotion_analysis():
    """Emotion Analysis page - requires login"""
    if 'user_id' not in session:
        flash('Please login to access emotion analysis.', 'error')
        return redirect(url_for('login_page'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('emotion_analysis.html', user=user)

@app.route('/auth/login', methods=['POST'])
def login():
    """Handle login form submission"""
    try:
        # Check rate limiting
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not check_rate_limit(client_ip):
            flash('Too many login attempts. Please try again in 15 minutes.', 'error')
            return redirect(url_for('login_page'))
        
        # Validate CSRF token
        # csrf_token = request.form.get('csrf_token')
        # if not validate_csrf_token(csrf_token):
        #     flash('Security token invalid. Please try again.', 'error')
        #     return redirect(url_for('login_page'))
        
        # Verify Turnstile CAPTCHA
        turnstile_token = request.form.get('cf-turnstile-response')
        if not verify_turnstile(turnstile_token):
            flash('Please complete the security verification.', 'error')
            return redirect(url_for('login_page'))
        
        # Get and validate input
        email = sanitize_input(request.form.get('email', ''), 254)
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me') == 'on'
        
        # Validate inputs
        validation_errors = validate_user_input(
            {'email': email, 'password': password},
            ['email', 'password'],
            {'email': validate_email}
        )
        
        if validation_errors:
            for error in validation_errors:
                flash(error, 'error')
            return redirect(url_for('login_page'))
        
        # Additional password length check for login
        if len(password) < 1 or len(password) > 128:
            flash('Invalid password', 'error')
            return redirect(url_for('login_page'))
        
        password_hash = hash_password(password)
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND password_hash = ?', 
                           (email, password_hash)).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            
            response = make_response(redirect(get_user_dashboard_url(user['id'])))
            
            if remember_me:
                # Create remember token and set cookie
                token = create_remember_token(user['id'])
                response.set_cookie('remember_token', token, 
                                  max_age=7*24*60*60,  # 7 days in seconds
                                  httponly=True, 
                                  secure=False,  # Set to True in production with HTTPS
                                  samesite='Lax')
            
            flash('Login successful!', 'success')
            return response
        else:
            # Record failed login attempt
            record_login_attempt(client_ip)
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login_page'))
    
    except Exception as e:
        # Record failed login attempt for exceptions too
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        record_login_attempt(client_ip)
        flash('An error occurred during login. Please try again.', 'error')
        return redirect(url_for('login_page'))

@app.route('/auth/register', methods=['POST'])
def register():
    """Handle registration form submission"""
    try:
        # Validate CSRF token
        # csrf_token = request.form.get('csrf_token')
        # if not validate_csrf_token(csrf_token):
        #     flash('Security token invalid. Please try again.', 'error')
        #     return redirect(url_for('register_page'))
        
        # Verify Turnstile CAPTCHA
        turnstile_token = request.form.get('cf-turnstile-response')
        if not verify_turnstile(turnstile_token):
            flash('Please complete the security verification.', 'error')
            return redirect(url_for('register_page'))
        
        # Get and validate input
        email = sanitize_input(request.form.get('email', ''), 254)
        password = request.form.get('password', '')
        
        # Validate email
        if not validate_email(email):
            flash('Please enter a valid email address', 'error')
            return redirect(url_for('register_page'))
        
        # Validate password
        password_errors = validate_password(password)
        if password_errors:
            for error in password_errors:
                flash(error, 'error')
            return redirect(url_for('register_page'))
        
        password_hash = hash_password(password)
        
        conn = get_db_connection()
        
        # Check if email already exists
        existing_user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if existing_user:
            flash('Email already registered.', 'error')
            conn.close()
            return redirect(url_for('register_page'))
        
        # Create new user
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', 
                       (email, password_hash))
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        session['user_id'] = user_id
        flash('Registration successful! Please complete your profile.', 'success')
        return redirect(url_for('complete_profile_page'))
    
    except Exception as e:
        flash('An error occurred during registration. Please try again.', 'error')
        return redirect(url_for('register_page'))

@app.route('/complete-profile')
def complete_profile_page():
    """Complete profile page"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('complete_profile.html')

@app.route('/auth/complete-profile', methods=['POST'])
def complete_profile():
    """Handle profile completion"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    try:
        # Get and sanitize input
        first_name = sanitize_input(request.form.get('first_name', ''), 50)
        last_name = sanitize_input(request.form.get('last_name', ''), 50)
        birthday = sanitize_input(request.form.get('birthday', ''), 10)
        country = sanitize_input(request.form.get('country', ''), 50)
        contact_number = sanitize_input(request.form.get('contact_number', ''), 20)
        
        # Validate inputs
        validation_errors = validate_user_input(
            {
                'first_name': first_name,
                'last_name': last_name,
                'birthday': birthday,
                'country': country
            },
            ['first_name', 'last_name', 'birthday', 'country'],
            {
                'first_name': validate_name,
                'last_name': validate_name,
                'birthday': validate_date,
                'country': validate_name
            }
        )
        
        # Validate contact number (optional but if provided, must be valid)
        if contact_number and not re.match(r'^\+?[\d\s\-\(\)]{7,20}$', contact_number):
            validation_errors.append('Invalid contact number format')
        
        if validation_errors:
            for error in validation_errors:
                flash(error, 'error')
            return redirect(url_for('complete_profile_page'))
        
        conn = get_db_connection()
        conn.execute('''UPDATE users SET first_name = ?, last_name = ?, birthday = ?, 
                        country = ?, contact_number = ? WHERE id = ?''',
                     (first_name, last_name, birthday, country, contact_number, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Profile completed successfully!', 'success')
        return redirect(url_for(get_user_dashboard_endpoint(session['user_id'])))
    
    except Exception as e:
        flash('An error occurred while updating your profile. Please try again.', 'error')
        return redirect(url_for('complete_profile_page'))

@app.route('/pair-teddy', methods=['POST'])
def pair_teddy():
    """Pair a teddy device with user account"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    try:
        # Get and validate teddy code
        teddy_code = sanitize_input(request.form.get('teddy_code', ''), 6)
        
        if not validate_teddy_code(teddy_code):
            return jsonify({'success': False, 'message': 'Invalid teddy code. Must be exactly 6 digits.'})
        
        conn = get_db_connection()
        
        # Check if teddy code is already paired
        existing_teddy = conn.execute('SELECT user_id FROM teddy_devices WHERE teddy_code = ?', 
                                     (teddy_code,)).fetchone()
        
        if existing_teddy and existing_teddy['user_id'] is not None:
            conn.close()
            return jsonify({'success': False, 'message': 'This teddy is already paired with another account.'})
        
        # Check if user already has a teddy paired
        user_teddy = conn.execute('SELECT teddy_code FROM teddy_devices WHERE user_id = ?', 
                                 (session['user_id'],)).fetchone()
        
        if user_teddy:
            conn.close()
            return jsonify({'success': False, 'message': 'You already have a teddy paired. Please unpair first.'})
        
        # Pair the teddy
        if existing_teddy:
            # Update existing teddy record
            conn.execute('UPDATE teddy_devices SET user_id = ? WHERE teddy_code = ?', 
                        (session['user_id'], teddy_code))
        else:
            # Create new teddy record
            conn.execute('INSERT INTO teddy_devices (teddy_code, user_id) VALUES (?, ?)', 
                        (teddy_code, session['user_id']))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Teddy paired successfully!'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': 'An error occurred while pairing the teddy.'})

@app.route('/logout')
def logout():
    """Logout user"""
    # Clear remember token if it exists
    remember_token = request.cookies.get('remember_token')
    if remember_token:
        delete_remember_token(remember_token)
    
    session.clear()
    flash('You have been logged out.', 'info')
    
    # Clear the remember token cookie
    response = make_response(redirect(url_for('landing_page')))
    response.set_cookie('remember_token', '', expires=0, httponly=True, secure=False)
    return response

@app.route('/unpair-teddy', methods=['POST'])
def unpair_teddy():
    """Unpair TEDDY device from user account"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    conn = get_db_connection()
    try:
        # Check if user has a teddy paired
        user_teddy = conn.execute('SELECT teddy_code FROM teddy_devices WHERE user_id = ?', 
                                 (session['user_id'],)).fetchone()
        
        if not user_teddy:
            conn.close()
            return jsonify({'success': False, 'message': 'No TEDDY device paired.'})
        
        # Remove user association but keep the device record
        conn.execute('UPDATE teddy_devices SET user_id = NULL WHERE user_id = ?', 
                    (session['user_id'],))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'TEDDY device unpaired successfully!'})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'})

@app.route('/delete-account', methods=['POST'])
def delete_account():
    """Delete user account and all associated data"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    try:
        # Get and validate password confirmation
        password = request.form.get('password', '')
        if not password or len(password) < 1 or len(password) > 128:
            return jsonify({'success': False, 'message': 'Password confirmation required'})
        
        password_hash = hash_password(password)
        
        conn = get_db_connection()
        
        # Verify password
        user = conn.execute('SELECT id FROM users WHERE id = ? AND password_hash = ?', 
                           (session['user_id'], password_hash)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid password'})
        
        # Remove user association from TEDDY devices (don't delete the devices)
        conn.execute('UPDATE teddy_devices SET user_id = NULL WHERE user_id = ?', 
                    (session['user_id'],))
        
        # Delete remember tokens for this user
        conn.execute('DELETE FROM remember_tokens WHERE user_id = ?', (session['user_id'],))
        
        # Delete user record
        conn.execute('DELETE FROM users WHERE id = ?', (session['user_id'],))
        
        conn.commit()
        conn.close()
        
        # Clear session
        session.clear()
        
        return jsonify({'success': True, 'message': 'Account deleted successfully'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': 'An error occurred while deleting your account.'})

# API Endpoints
@app.route('/api/receive-data', methods=['POST'])
def receive_data():
    """API endpoint for teddy to send data"""
    # Validate API key
    if not validate_api_key():
        return jsonify({'success': False, 'message': 'Invalid or missing API key'}), 401
    
    try:
        data = request.get_json()
        
        if not data or 'teddycode' not in data or 'battery' not in data:
            return jsonify({'success': False, 'message': 'Invalid data format'}), 400
        
        teddy_code = data['teddycode']
        battery = int(data['battery'])
        
        if len(teddy_code) != 6 or not teddy_code.isdigit():
            return jsonify({'success': False, 'message': 'Invalid teddy code'}), 400
        
        if battery < 0 or battery > 100:
            return jsonify({'success': False, 'message': 'Invalid battery level'}), 400
        
        conn = get_db_connection()
        
        # Update or create teddy device record
        existing_teddy = conn.execute('SELECT id FROM teddy_devices WHERE teddy_code = ?', 
                                     (teddy_code,)).fetchone()
        
        if existing_teddy:
            conn.execute('UPDATE teddy_devices SET battery_level = ?, last_updated = CURRENT_TIMESTAMP WHERE teddy_code = ?', 
                        (battery, teddy_code))
        else:
            conn.execute('INSERT INTO teddy_devices (teddy_code, battery_level) VALUES (?, ?)', 
                        (teddy_code, battery))
        
        # Log the data
        conn.execute('INSERT INTO teddy_logs (teddy_code, battery_level) VALUES (?, ?)', 
                    (teddy_code, battery))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Data received successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    """Edit user profile with password confirmation"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if request.method == 'POST':
        # Get form data
        current_password = request.form.get('current_password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        birthday = request.form.get('birthday')
        country = request.form.get('country')
        contact_number = request.form.get('contact_number')
        
        # Verify current password
        password_hash = hashlib.sha256(current_password.encode()).hexdigest()
        if password_hash != user['password_hash']:
            conn.close()
            return jsonify({'success': False, 'message': 'Current password is incorrect'})
        
        # Update profile
        conn.execute('''UPDATE users SET 
                        first_name = ?, last_name = ?, birthday = ?, 
                        country = ?, contact_number = ? 
                        WHERE id = ?''', 
                    (first_name, last_name, birthday, country, contact_number, session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Profile updated successfully!'})
    
    conn.close()
    return render_template('edit_profile.html', user=user)

@app.route('/api/broadcast-teddy', methods=['GET'])
def broadcast_teddy():
    """API endpoint for teddy to get target user data"""
    # Validate API key
    if not validate_api_key():
        return jsonify({'success': False, 'message': 'Invalid or missing API key'}), 401
    
    teddy_code = request.args.get('teddycode')
    
    if not teddy_code or len(teddy_code) != 6 or not teddy_code.isdigit():
        return jsonify({'success': False, 'message': 'Invalid teddy code'}), 400
    
    conn = get_db_connection()
    teddy = conn.execute('SELECT teddy_code FROM teddy_devices WHERE teddy_code = ? AND user_id IS NOT NULL', 
                        (teddy_code,)).fetchone()
    conn.close()
    
    if not teddy:
        return jsonify({'success': False, 'message': 'Teddy not found or not paired'}), 404
    
    return jsonify({
        'success': True,
        'teddycode': teddy_code,
        'status': 'paired'
    })

# Admin routes
@app.route('/admin')
@require_admin
def admin_dashboard():
    """Admin dashboard for user management"""
    conn = get_db_connection()
    
    # Get all users
    users = conn.execute('''
        SELECT u.*, 
               COUNT(td.id) as teddy_count,
               MAX(td.last_updated) as last_activity
        FROM users u
        LEFT JOIN teddy_devices td ON u.id = td.user_id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    ''').fetchall()
    
    # Get current admin user
    admin_user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Calculate statistics
    total_users = len(users)
    admin_users = len([u for u in users if u['is_admin'] == 1])
    total_teddy_devices = sum(u['teddy_count'] for u in users)
    
    # Get users created this month
    from datetime import datetime
    current_month = datetime.now().strftime('%Y-%m')
    users_this_month = len([u for u in users if u['created_at'] and u['created_at'].startswith(current_month)])
    
    stats = {
        'total_users': total_users,
        'admin_users': admin_users,
        'users_this_month': users_this_month,
        'total_teddy_devices': total_teddy_devices
    }
    
    conn.close()
    
    return render_template('admin_dashboard.html', users=users, admin_user=admin_user, stats=stats)

@app.route('/admin/user/<int:user_id>')
@require_admin
def admin_user_details(user_id):
    """View detailed user information"""
    conn = get_db_connection()
    
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Get user's TEDDY devices
    devices = conn.execute('SELECT * FROM teddy_devices WHERE user_id = ?', (user_id,)).fetchall()
    
    # Get user's logs
    logs = conn.execute('''
        SELECT tl.*, td.teddy_code 
        FROM teddy_logs tl
        JOIN teddy_devices td ON tl.teddy_code = td.teddy_code
        WHERE td.user_id = ?
        ORDER BY tl.timestamp DESC
        LIMIT 50
    ''', (user_id,)).fetchall()
    
    conn.close()
    
    return render_template('admin_user_details.html', user=user, devices=devices, logs=logs)

@app.route('/admin/user/<int:user_id>/toggle-admin', methods=['POST'])
@require_admin
def admin_toggle_admin_status(user_id):
    """Toggle admin status for a user"""
    if user_id == session['user_id']:
        flash('You cannot change your own admin status.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    new_admin_status = 1 if user['is_admin'] == 0 else 0
    conn.execute('UPDATE users SET is_admin = ? WHERE id = ?', (new_admin_status, user_id))
    conn.commit()
    conn.close()
    
    action = 'granted' if new_admin_status else 'revoked'
    flash(f'Admin access {action} for {user["email"]}.', 'success')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@require_admin
def admin_delete_user(user_id):
    """Delete a user account"""
    if user_id == session['user_id']:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Delete user's TEDDY devices and logs
    conn.execute('DELETE FROM teddy_logs WHERE teddy_code IN (SELECT teddy_code FROM teddy_devices WHERE user_id = ?)', (user_id,))
    conn.execute('DELETE FROM teddy_devices WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash(f'User {user["email"]} has been deleted.', 'success')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/stats')
@require_admin
def admin_stats():
    """Admin statistics page"""
    conn = get_db_connection()
    
    # Get various statistics
    stats = {}
    
    # User statistics
    stats['total_users'] = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    stats['admin_users'] = conn.execute('SELECT COUNT(*) FROM users WHERE is_admin = 1').fetchone()[0]
    stats['users_this_month'] = conn.execute('''
        SELECT COUNT(*) FROM users 
        WHERE created_at >= date('now', 'start of month')
    ''').fetchone()[0]
    
    # Device statistics
    stats['total_devices'] = conn.execute('SELECT COUNT(*) FROM teddy_devices').fetchone()[0]
    stats['paired_devices'] = conn.execute('SELECT COUNT(*) FROM teddy_devices WHERE user_id IS NOT NULL').fetchone()[0]
    stats['active_devices'] = conn.execute('''
        SELECT COUNT(*) FROM teddy_devices 
        WHERE last_updated >= datetime('now', '-7 days')
    ''').fetchone()[0]
    
    # Recent activity
    recent_users = conn.execute('''
        SELECT email, first_name, last_name, created_at 
        FROM users 
        ORDER BY created_at DESC 
        LIMIT 10
    ''').fetchall()
    
    recent_devices = conn.execute('''
        SELECT td.teddy_code, u.email, td.last_updated
        FROM teddy_devices td
        LEFT JOIN users u ON td.user_id = u.id
        ORDER BY td.last_updated DESC
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin_stats.html', stats=stats, recent_users=recent_users, recent_devices=recent_devices)

@app.route('/admin/user/<int:user_id>/reset-password', methods=['POST'])
@require_admin
def admin_reset_password(user_id):
    """Reset user password"""
    try:
        data = request.get_json()
        new_password = data.get('new_password')
        
        if not new_password or len(new_password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'})
        
        # Hash the new password
        import hashlib
        password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        
        conn = get_db_connection()
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Password reset successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/device/<teddy_code>/unpair', methods=['POST'])
@require_admin
def admin_unpair_device(teddy_code):
    """Unpair a TEDDY device from user"""
    try:
        conn = get_db_connection()
        
        # Check if device exists
        device = conn.execute('SELECT * FROM teddy_devices WHERE teddy_code = ?', (teddy_code,)).fetchone()
        if not device:
            conn.close()
            return jsonify({'success': False, 'message': 'Device not found'})
        
        # Delete device logs first
        conn.execute('DELETE FROM teddy_logs WHERE teddy_code = ?', (teddy_code,))
        
        # Remove user association (unpair)
        conn.execute('UPDATE teddy_devices SET user_id = NULL WHERE teddy_code = ?', (teddy_code,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': f'Device {teddy_code} unpaired successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# Emotion Analysis API Endpoints
@app.route('/api/emotion/text', methods=['POST'])
def api_emotion_text():
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({"error": "Missing text in request"}), 400
        
        result = emotion_api.analyze_text_emotion(data['text'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/emotion/audio', methods=['POST'])
def api_emotion_audio():
    try:
        if 'audio' not in request.files:
            return jsonify({"error": "No audio file provided"}), 400
        
        audio_file = request.files['audio']
        
        # Save temporarily
        temp_path = f"temp_audio_{uuid.uuid4().hex[:8]}.mp3"
        audio_file.save(temp_path)
        
        try:
            result = emotion_api.analyze_audio_file(temp_path)
            return jsonify(result)
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/emotion/image', methods=['POST'])
def api_emotion_image():
    try:
        if 'image' not in request.files:
            return jsonify({"error": "No image file provided"}), 400
        
        image_file = request.files['image']
        
        # Save temporarily
        temp_path = f"temp_image_{uuid.uuid4().hex[:8]}.jpg"
        image_file.save(temp_path)
        
        try:
            result = emotion_api.analyze_image_file(temp_path)
            return jsonify(result)
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ESP32-specific endpoints for raw binary data
@app.route('/api/esp32/analyze/image', methods=['POST'])
def api_esp32_image():
    """ESP32 endpoint for raw JPEG image analysis with database storage"""
    try:
        # Get TEDDY code from headers or form data
        teddy_code = request.headers.get('X-TEDDY-Code') or request.args.get('teddy_code')
        if not teddy_code:
            return jsonify({"error": "Missing TEDDY code in headers (X-TEDDY-Code) or query params"}), 400
        
        # Validate TEDDY code exists in database
        conn = sqlite3.connect(config['database_path'])
        cursor = conn.cursor()
        cursor.execute('SELECT teddy_code FROM teddy_devices WHERE teddy_code = ?', (teddy_code,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Invalid TEDDY code"}), 400
        conn.close()
        
        # Get raw JPEG data
        if request.content_type == 'image/jpeg':
            # Raw JPEG bytes in request body
            jpeg_data = request.get_data()
        elif 'image' in request.files:
            # File upload
            jpeg_data = request.files['image'].read()
        else:
            return jsonify({"error": "No image data provided. Send raw JPEG as body with content-type image/jpeg or as file upload"}), 400
        
        if not jpeg_data:
            return jsonify({"error": "Empty image data"}), 400
        
        # Save temporarily for processing
        temp_path = f"temp_esp32_image_{uuid.uuid4().hex[:8]}.jpg"
        
        try:
            with open(temp_path, 'wb') as f:
                f.write(jpeg_data)
            
            # Analyze the image
            result = emotion_api.analyze_image_file(temp_path)
            
            # Store result in database
            if emotion_api.store_emotion_result(teddy_code, result, 'image'):
                result['stored'] = True
                result['teddy_code'] = teddy_code
            else:
                result['stored'] = False
                result['warning'] = 'Analysis completed but failed to store in database'
            
            return jsonify(result)
            
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        print(f"ESP32 image analysis error: {e}")
        return jsonify({"error": str(e), "teddy_code": teddy_code if 'teddy_code' in locals() else "unknown"}), 500

@app.route('/api/esp32/analyze/audio', methods=['POST'])
def api_esp32_audio():
    """ESP32 endpoint for WAV audio analysis with database storage"""
    try:
        # Get TEDDY code from headers or form data
        teddy_code = request.headers.get('X-TEDDY-Code') or request.form.get('teddy_code') or request.args.get('teddy_code')
        if not teddy_code:
            return jsonify({"error": "Missing TEDDY code in headers (X-TEDDY-Code), form data, or query params"}), 400
        
        # Validate TEDDY code exists in database
        conn = sqlite3.connect(config['database_path'])
        cursor = conn.cursor()
        cursor.execute('SELECT teddy_code FROM teddy_devices WHERE teddy_code = ?', (teddy_code,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Invalid TEDDY code"}), 400
        conn.close()
        
        # Get WAV audio data
        if 'audio' in request.files:
            # Multipart form data upload
            audio_file = request.files['audio']
            audio_data = audio_file.read()
        elif request.content_type == 'audio/wav':
            # Raw WAV bytes in request body
            audio_data = request.get_data()
        else:
            return jsonify({"error": "No audio data provided. Send as multipart form-data or raw WAV with content-type audio/wav"}), 400
        
        if not audio_data:
            return jsonify({"error": "Empty audio data"}), 400
        
        # Save temporarily for processing
        temp_path = f"temp_esp32_audio_{uuid.uuid4().hex[:8]}.wav"
        
        try:
            with open(temp_path, 'wb') as f:
                f.write(audio_data)
            
            # Analyze the audio
            result = emotion_api.analyze_audio_file(temp_path)
            
            # Store result in database
            if emotion_api.store_emotion_result(teddy_code, result, 'audio'):
                result['stored'] = True
                result['teddy_code'] = teddy_code
            else:
                result['stored'] = False
                result['warning'] = 'Analysis completed but failed to store in database'
            
            return jsonify(result)
            
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        print(f"ESP32 audio analysis error: {e}")
        return jsonify({"error": str(e), "teddy_code": teddy_code if 'teddy_code' in locals() else "unknown"}), 500

@app.route('/api/esp32/emotion/latest/<teddy_code>', methods=['GET'])
def api_esp32_latest_emotion(teddy_code):
    """Get the latest emotion analysis result for a TEDDY device"""
    try:
        result = emotion_api.get_latest_emotion(teddy_code)
        return jsonify(result)
    except Exception as e:
        print(f"Error getting latest emotion for {teddy_code}: {e}")
        return jsonify({"error": str(e), "teddy_code": teddy_code}), 500

@app.route('/api/emotion/health', methods=['GET'])
def api_emotion_health():
    try:
        result = emotion_api.health_check()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    init_db()
    create_admin_user()
    app.run(host='0.0.0.0', port=2614)
