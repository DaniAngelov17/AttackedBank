import re
import logging
from logging.handlers import RotatingFileHandler
import datetime
import os
import bcrypt  # <-- ADD THIS
from flask import Flask, request, redirect, url_for, session, render_template, jsonify, abort
from database_manager import DatabaseManager
from user import User

app = Flask(__name__)
app.secret_key = 'SOME_SECRET_KEY'  # Replace with a secure random value in production

# --------------------------------------------------------------------------
# 1. Configure Logging
# --------------------------------------------------------------------------
log_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log_file = "secure_app.log"
log_handler = RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=5)
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.INFO)

app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)
# End of logging configuration

# Initialize the database manager
db_manager = DatabaseManager()

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

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user already exists
        if db_manager.user_exists(username):
            error = "Username already taken, please choose another."
        else:
            # Enforce strong password requirement
            if not is_strong_password(password):
                error = (
                    "Password too weak! Must be at least 8 characters and include "
                    "uppercase, lowercase, digits, and special characters."
                )
            else:
                # Hash the password + salt (bcrypt handles salting internally)
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

                # Create user in DB with hashed password
                db_manager.create_user(username, hashed_password.decode('utf-8'))

                app.logger.info(f"New user created: '{username}' (password hashed)")
                return redirect(url_for('login'))

    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Log method and endpoint
    app.logger.debug(f"Received {request.method} request at /login")

    error = None
    if request.method == 'POST':
        app.logger.debug(f"Request headers: {dict(request.headers)}")

        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            app.logger.info(f"Login attempt via JSON for user: '{username}'")
        else:
            username = request.form.get('username')
            password = request.form.get('password')
            app.logger.info(f"Login attempt via Form for user: '{username}'")

        if not username or not password:
            app.logger.warning("Missing username or password in login request.")
            return jsonify({"error": "Missing username or password"}), 400

        # Validate credentials (hashed password check)
        user_row = db_manager.validate_credentials(username, password)
        if user_row:
            session['username'] = user_row[0]
            app.logger.info(f"User '{username}' logged in successfully.")
            return redirect(url_for('dashboard'))
        else:
            app.logger.warning(f"Invalid login attempt for user '{username}'")
            error = "Invalid username or password."

    return render_template('login.html', error=error)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    """Display and handle money transfers."""
    if 'username' not in session:
        app.logger.info("Unauthorized dashboard access attempt. Redirecting to login.")
        return redirect(url_for('login'))

    username = session['username']
    user_row = db_manager.get_user(username)
    if not user_row:
        app.logger.warning(f"Session user '{username}' not found in DB. Logging out.")
        return redirect(url_for('logout'))

    current_user = User(user_row[0], user_row[1], user_row[2], user_row[3])
    transfer_message = None
    error = None

    if request.method == 'POST':
        target_user_name = request.form['target_user']
        attack_explanation = request.form.get('attack_explanation')  # Provided if admin
        amount_str = request.form.get('amount')

        try:
            amount = float(amount_str)
        except (ValueError, TypeError):
            error = "Invalid amount."
            app.logger.debug(
                f"User '{username}' entered invalid amount '{amount_str}'"
            )
            return render_template(
                'dashboard.html',
                username=current_user.username,
                balance=current_user.balance,
                transfer_message=transfer_message,
                error=error
            )

        if current_user.username == 'admin':
            if not attack_explanation or not attack_explanation.strip():
                error = "Admin must provide an explanation of how attackers got in."
                return render_template(
                    'dashboard.html',
                    username=current_user.username,
                    balance=current_user.balance,
                    transfer_message=transfer_message,
                    error=error
                )
            else:
                # Log the explanation
                log_filename = "attack_log.txt"
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_entry = f"[{timestamp}] Admin Explanation: {attack_explanation}\n"
                with open(log_filename, "a", encoding="utf-8") as log_file:
                    log_file.write(log_entry)
                app.logger.info("Admin provided an attack explanation.")

        if amount <= 0:
            error = "Transfer amount must be greater than 0."
        elif amount > current_user.balance:
            error = "Insufficient balance."
            app.logger.warning(
                f"User '{username}' attempted to transfer more than their balance."
            )
        else:
            # Check if target user exists
            target_row = db_manager.get_user(target_user_name)
            if not target_row:
                error = f"User '{target_user_name}' does not exist."
                app.logger.warning(
                    f"User '{username}' attempted transfer to non-existent user '{target_user_name}'."
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
