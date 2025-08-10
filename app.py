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
    if not token:
        return False
    
    secret_key = config.get('turnstile', {}).get('secret_key', '')
    
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

# Make CSRF token available to all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())

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
                "site_key": "",
                "secret_key": ""
            }
        }
        with open('config.json', 'w') as f:
            json.dump(default_config, f, indent=4)
        return default_config

config = load_config()
app.secret_key = config['secret_key']

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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
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
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    """Registration page"""
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard page - requires login"""
    if 'user_id' not in session:
        flash('Please login to access the dashboard.', 'error')
        return redirect(url_for('login_page'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    teddy = conn.execute('SELECT * FROM teddy_devices WHERE user_id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('dashboard.html', user=user, teddy=teddy)

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
            
            response = make_response(redirect(url_for('dashboard')))
            
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
        return redirect(url_for('dashboard'))
    
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

@app.route('/update-target-user', methods=['POST'])
def update_target_user():
    """Update target user for teddy"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    try:
        # Get and validate target user
        target_user = sanitize_input(request.form.get('target_user', ''), 20)
        valid_targets = ['Children', 'Teens', 'Adults', 'Elderly', 'Autistic', 'Anxious', 'Patients']
        
        if target_user not in valid_targets:
            return jsonify({'success': False, 'message': 'Invalid target user selection'})
        
        conn = get_db_connection()
        
        # Check if user has a teddy paired first
        user_teddy = conn.execute('SELECT teddy_code FROM teddy_devices WHERE user_id = ?', 
                                 (session['user_id'],)).fetchone()
        
        if not user_teddy:
            conn.close()
            return jsonify({'success': False, 'message': 'No TEDDY device paired. Please pair a device first.'})
        
        # Update target user
        conn.execute('UPDATE teddy_devices SET target_user = ? WHERE user_id = ?', 
                    (target_user, session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Target user updated successfully!'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': 'An error occurred while updating target user.'})
        conn.close()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'})

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
    teddy = conn.execute('SELECT target_user FROM teddy_devices WHERE teddy_code = ? AND user_id IS NOT NULL', 
                        (teddy_code,)).fetchone()
    conn.close()
    
    if not teddy:
        return jsonify({'success': False, 'message': 'Teddy not found or not paired'}), 404
    
    return jsonify({
        'success': True,
        'teddycode': teddy_code,
        'target_user': teddy['target_user']
    })

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
