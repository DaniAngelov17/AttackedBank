import re
import logging
import random
from logging.handlers import RotatingFileHandler
import os
import bcrypt
import secrets
import time
from datetime import timedelta, datetime

import requests  # Optional, if used somewhere else
from flask import Flask, request, redirect, url_for, session, render_template, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask.logging import default_handler

from database_manager import DatabaseManager
from user import User
from functools import wraps

##############################################################################
# Flask Application Setup
##############################################################################
app = Flask(__name__)

# --------------------------------------------------------------------------
# 1. Configure Security & Session
# --------------------------------------------------------------------------
# Generate a random secret key at startup.
# In production, you might load this from a secure place like an env variable.
app.secret_key = secrets.token_hex(32)

# Session security settings
app.config.update(
    SESSION_COOKIE_SECURE=False,      # True if you have HTTPS
    SESSION_COOKIE_HTTPONLY=True,     # Prevent JavaScript access to session cookie
    SESSION_COOKIE_SAMESITE='Lax',    # Helps protect against CSRF
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=5)  # Session expires after 5 min of inactivity
)

# --------------------------------------------------------------------------
# 2. Configure Logging (Rotating File Handler)
# --------------------------------------------------------------------------
log_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log_file = "secure_app.log"

# Remove default Flask logger to avoid duplicates
app.logger.removeHandler(default_handler)

# Set up rotating file handler
log_handler = RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=5)
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.INFO)

app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)

# Suppress overly verbose werkzeug logs, except for errors
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# --------------------------------------------------------------------------
# 3. Create and Configure Database Manager
# --------------------------------------------------------------------------
db_manager = DatabaseManager()

##############################################################################
# Helper Functions
##############################################################################
def login_limit_key():
    """
    Custom rate-limit key:
      - IP address + username (if provided) 
    """
    ip = get_remote_address()
    username = request.form.get('username', 'no_user')
    return f"{ip}-{username}"

def is_strong_password(password):
    """
    Return True if the password is at least 8 characters long,
    and contains uppercase, lowercase, digit, and special character.
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    special_chars_pattern = r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]"
    if not re.search(special_chars_pattern, password):
        return False
    return True

def generate_captcha():
    """
    Generates a simple math CAPTCHA question and stores the answer in the session.
    """
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    session['captcha_answer'] = str(num1 + num2)
    return f"{num1} + {num2} = ?"

##############################################################################
# Flask-Limiter Setup
##############################################################################
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

##############################################################################
# Routes
##############################################################################
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Handles user signup:
     - Checks if passwords match (if confirm_password is provided)
     - Ensures username doesn't already exist
     - Enforces strong password requirements
     - Hashes the password with bcrypt
     - Creates the user in the DB
    """
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password', '')

        # Check password confirmation
        if confirm_password and (password != confirm_password):
            error = "Passwords do not match."
        # Check if user already exists
        elif db_manager.user_exists(username):
            error = f"Username '{username}' already taken, please choose another."
        else:
            # Validate password strength
            if not is_strong_password(password):
                error = (
                    "Password too weak! Must be at least 8 characters and include "
                    "uppercase, lowercase, digits, and special characters."
                )
            else:
                # Hash the password
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                # Store user in DB with hashed password (as UTF-8 string)
                db_manager.create_user(username, hashed_password.decode('utf-8'))
                app.logger.info(f"New user created: '{username}' (password hashed)")
                return redirect(url_for('login'))

    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"], key_func=login_limit_key)
def login():
    """
    Handles user login with a simple math CAPTCHA for bot prevention.
    - Validates CAPTCHA answer before processing login.
    - Logs invalid attempts, successful logins, and missing credentials.
    """
    user_ip = request.remote_addr
    error = None

    if request.method == 'GET':
        session['captcha_question'] = generate_captcha()
        return render_template('login.html', error=error, captcha_question=session['captcha_question'])

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        captcha_input = request.form.get('captcha')

        # Basic check for empty fields
        if not username or not password or not captcha_input:
            app.logger.warning(f"Missing login credentials from IP {user_ip}.")
            session['captcha_question'] = generate_captcha()
            return render_template('login.html', 
                                   error="Please fill in all fields and complete the CAPTCHA.",
                                   captcha_question=session['captcha_question'])

        # CAPTCHA Validation
        if captcha_input.strip() != session.get('captcha_answer'):
            app.logger.warning(f"Failed CAPTCHA for user '{username}' from IP {user_ip}.")
            session['captcha_question'] = generate_captcha()
            return render_template('login.html', 
                                   error="Incorrect CAPTCHA. Try again.",
                                   captcha_question=session['captcha_question'])

        # Check credentials (Example: only 'admin' with a known strong password)
        # Replace this with a real DB check in production.
        if username == "admin" and password == "V3yT@By>%w3[cXlI":
            # Successful login
            session.clear()
            session.permanent = True
            session['username'] = username
            session['last_activity'] = datetime.now().timestamp()
            app.logger.info(f"User '{username}' logged in successfully from IP {user_ip}.")
            return redirect(url_for('dashboard'))
        else:
            # Invalid login attempt
            app.logger.warning(f"Invalid login attempt for user '{username}' from IP {user_ip}.")
            # Delay to mitigate brute-force
            time.sleep(2)
            # Renew CAPTCHA
            session['captcha_question'] = generate_captcha()
            return render_template('login.html',
                                   error="Invalid username or password.",
                                   captcha_question=session['captcha_question'])

    return render_template('login.html', error=error)

def login_required(f):
    """
    Decorator to ensure the user is logged in (and session hasn't expired) 
    before accessing certain routes (like dashboard).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in
        if 'username' not in session:
            return redirect(url_for('login'))

        last_activity = session.get('last_activity')
        if not last_activity:
            session.clear()
            return redirect(url_for('login'))

        # Check if session has timed out
        idle_time = datetime.now().timestamp() - last_activity
        if idle_time > app.config['PERMANENT_SESSION_LIFETIME'].total_seconds():
            app.logger.info(f"Session for user '{session.get('username')}' timed out due to inactivity.")
            session.clear()
            return redirect(url_for('login'))

        # Update the last activity time
        session['last_activity'] = datetime.now().timestamp()
        return f(*args, **kwargs)
    return decorated_function

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    """
    Displays the user dashboard and handles money transfers.
    Only accessible if logged in.
    """
    username = session['username']
    user_row = db_manager.get_user(username)
    if not user_row:
        # If the user doesn't exist in DB for some reason
        app.logger.warning(f"Session user '{username}' not found in DB. Logging out.")
        return redirect(url_for('logout'))

    # Construct the current_user from DB record
    current_user = User(user_row[0], user_row[1], user_row[2], user_row[3])
    transfer_message = None
    error = None

    if request.method == 'POST':
        target_user_name = request.form.get('target_user', '')
        amount_str = request.form.get('amount', '0')
        attack_explanation = request.form.get('attack_explanation', '')  # If admin

        # Validate the amount
        try:
            amount = float(amount_str)
        except ValueError:
            error = "Invalid amount."
            app.logger.debug(f"User '{username}' entered invalid amount '{amount_str}'")
            return render_template(
                'dashboard.html',
                username=current_user.username,
                balance=current_user.balance,
                transfer_message=None,
                error=error
            )

        # If the amount exceeds 10,000, adjust it and notify the user
        MAX_TRANSFER_AMOUNT = 10_000
        if amount > MAX_TRANSFER_AMOUNT:
            error = f"Maximum transfer limit is {MAX_TRANSFER_AMOUNT}. Amount adjusted to {MAX_TRANSFER_AMOUNT}."
            app.logger.warning(f"User '{username}' attempted to transfer more than {MAX_TRANSFER_AMOUNT}.")
            amount = MAX_TRANSFER_AMOUNT

        # If admin, require explanation
        if current_user.username == 'admin':
            if not attack_explanation.strip():
                error = "Admin must provide an explanation of how attackers got in."
                return render_template(
                    'dashboard.html',
                    username=current_user.username,
                    balance=current_user.balance,
                    transfer_message=None,
                    error=error
                )
            else:
                # Write explanation to a separate file
                log_filename = "attack_log_secure.txt"
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                # Minimal sanitization to avoid newlines hijack
                sanitized_explanation = attack_explanation.replace("\n", " ").replace("\r", " ")
                log_entry = f"[{timestamp}] Admin Explanation: {sanitized_explanation}\n"
                with open(log_filename, "a", encoding="utf-8") as f:
                    f.write(log_entry)
                app.logger.info("Admin provided an attack explanation.")

        if amount <= 0:
            error = "Transfer amount must be greater than 0."
        elif amount > current_user.balance:
            error = "Insufficient balance."
            app.logger.warning(f"User '{username}' attempted to transfer more than their balance.")
        else:
            # Check if target user exists
            target_row = db_manager.get_user(target_user_name)
            if not target_row:
                error = f"User '{target_user_name}' does not exist."
                app.logger.warning(
                    f"User '{username}' attempted to transfer to non-existent user '{target_user_name}'."
                )
            else:
                # Perform the transfer
                current_user.withdraw(amount)
                db_manager.update_balance(current_user.username, current_user.balance)

                target_user = User(target_row[0], target_row[1], target_row[2], target_row[3])
                target_user.deposit(amount)
                db_manager.update_balance(target_user.username, target_user.balance)

                transfer_message = f"Successfully transferred {amount} to {target_user_name}!"
                app.logger.info(
                    f"User '{username}' transferred {amount} to '{target_user_name}'. "
                    f"New balance: {current_user.balance}"
                )

    return render_template(
        'dashboard.html',
        username=current_user.username,
        balance=current_user.balance,
        transfer_message=transfer_message,
        error=error
    )

@app.route('/logout')
def logout():
    user = session.pop('username', None)
    if user:
        app.logger.info(f"User '{user}' logged out.")
    return redirect(url_for('login'))

# ----------------------------------------------------------------------------
# Optional: Simple IP Whitelisting (commented out by default)
# ----------------------------------------------------------------------------
# @app.before_request
# def limit_remote_addr():
#     allowed_ips = ["127.0.0.1", "192.168.2.8"]
#     if request.remote_addr not in allowed_ips:
#         app.logger.warning(f"Blocked request from non-whitelisted IP: {request.remote_addr}")
#         abort(403)  # Forbidden

# ----------------------------------------------------------------------------
# Main Entry
# ----------------------------------------------------------------------------
if __name__ == '__main__':
    # In production, set debug=False and run behind a production server (e.g., gunicorn/uWSGI)
    app.run(host='0.0.0.0', port=5001, debug=False)
