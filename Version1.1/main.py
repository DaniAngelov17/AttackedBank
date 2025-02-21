import re
import logging
import datetime  # <-- For timestamps
import sqlite3
from flask import Flask, request, redirect, url_for, session, render_template, flash

app = Flask(__name__)
app.secret_key = 'SOME_SECRET_KEY'  # Hardcoded weak secret key (Security Misconfiguration)

# Configure logging to output debug-level logs to a file (or to console)
logging.basicConfig(
    filename='insecure_app.log',  # You can change this to None to log to console instead
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s'
)

# Database connection
conn = sqlite3.connect('usersWeak.db', check_same_thread=False)
cursor = conn.cursor()

# Ensure users table exists
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT,  -- Stored in plaintext (Cryptographic Failures)
        balance REAL
    )
''')
conn.commit()

# Insert a default admin account
cursor.execute("INSERT OR IGNORE INTO users (username, password, balance) VALUES (?, ?, ?)",
               ('admin', 'admin123', 10000000.0))  # Weak password (Identification and Authentication Failures)
conn.commit()

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            error = "Username already taken, please choose another."
        else:
            # Create new user
            cursor.execute("INSERT INTO users (username, password, balance) VALUES (?, ?, ?)",
                           (username, password, 0.0))
            conn.commit()
            return redirect(url_for('login'))

    return render_template('signup.html', error=error)

def authenticate(username, password):
    """
    Vulnerable authentication function allowing SQL injection.
    """
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"  # (Injection)
    cursor.execute(query)
    return cursor.fetchone()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # -------------------------------------------
        # Insecurely log sensitive information here:
        logging.debug(f"User login attempt: username={username} with password={password}")
        # -------------------------------------------
        
        user = authenticate(username, password)
        if user:
            session['username'] = username  # Weak session handling
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid credentials."
    
    return render_template('login.html', error=error)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        return redirect(url_for('logout'))
    
    balance = user[2]
    error = None

    if request.method == 'POST':
        target_user = request.form['target_user']
        amount_str = request.form['amount']

        try:
            amount = float(amount_str)
        except ValueError:
            error = "Invalid amount entered."
            flash(error, "danger")
            return redirect(url_for('dashboard'))

        # NEW: Enforce transfer limit
        MAX_TRANSFER_AMOUNT = 10_000
        if amount > MAX_TRANSFER_AMOUNT:
            amount = MAX_TRANSFER_AMOUNT
            error = f"Maximum transfer limit is {MAX_TRANSFER_AMOUNT}. Amount adjusted automatically."
            flash(error, "warning")

        cursor.execute("SELECT * FROM users WHERE username = ?", (target_user,))
        target = cursor.fetchone()

        if target:
            if amount > balance:
                flash("Insufficient balance.", "danger")
            else:
                new_balance = balance - amount
                cursor.execute("UPDATE users SET balance = ? WHERE username = ?", (new_balance, username))
                cursor.execute("UPDATE users SET balance = ? WHERE username = ?", (target[2] + amount, target_user))
                conn.commit()

                flash(f"Successfully transferred {amount} to {target_user}", "success")
                return redirect(url_for('dashboard'))
        else:
            flash("User not found.", "danger")

    return render_template('dashboard.html', username=username, balance=balance)


@app.route('/admin')
def admin_panel():
    """
    Broken Access Control: Any user can access admin panel.
    """
    session['username'] = 'admin'  # Automatically set session to admin
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Debug enabled in production (Security Misconfiguration)
    app.run(host='0.0.0.0', port=8000, debug=True)
