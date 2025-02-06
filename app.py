from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'SOME_SECRET_KEY'  # Required to use sessions. Use a better secret in production.

# --------------------------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------------------------
def init_db():
    """Initialize the SQLite database and create the 'users' table if it doesn't exist."""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Create a table with columns for username, password, notes, and balance
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            notes TEXT,
            balance REAL
        )
    ''')
    # Insert a default admin user with some initial balance if not already present
    c.execute("""
        INSERT OR IGNORE INTO users (username, password, notes, balance) 
        VALUES (?, ?, ?, ?)
    """, ('admin', 'admin123', 'Secret admin notes', 100.0))
    conn.commit()
    conn.close()


# --------------------------------------------------------------------
# TEMPLATES
# (Using render_template_string here for compactness. 
#  You may use separate HTML files with render_template in a real app.)
# --------------------------------------------------------------------
SIGNUP_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>Sign Up</title></head>
<body>
    <h1>Sign Up</h1>
    <form method="POST">
        <p>
            <label>Username:</label>
            <input type="text" name="username" required>
        </p>
        <p>
            <label>Password:</label>
            <input type="password" name="password" required>
        </p>
        <input type="submit" value="Sign Up">
    </form>
    <p>
       Already have an account? <a href="{{ url_for('login') }}">Log in</a>
    </p>
    {% if error %}
    <p style="color: red;">{{ error }}</p>
    {% endif %}
</body>
</html>
'''

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h1>Login</h1>
    <form method="POST">
        <p>
            <label>Username:</label>
            <input type="text" name="username" required>
        </p>
        <p>
            <label>Password:</label>
            <input type="password" name="password" required>
        </p>
        <input type="submit" value="Login">
    </form>
    <p>
       Don't have an account? <a href="{{ url_for('signup') }}">Sign up</a>
    </p>
    {% if error %}
    <p style="color: red;">{{ error }}</p>
    {% endif %}
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
    <h1>Welcome, {{ username }}!</h1>
    <p>Your current balance: {{ balance }}</p>
    <hr>
    <h2>Transfer (Deposit) Money</h2>
    <form method="POST">
        <p>
            <label>Destination Username:</label>
            <input type="text" name="target_user" required>
        </p>
        <p>
            <label>Amount to Transfer:</label>
            <input type="number" step="0.01" name="amount" required>
        </p>
        <input type="submit" value="Transfer">
    </form>
    {% if transfer_message %}
    <p style="color: green;">{{ transfer_message }}</p>
    {% endif %}
    {% if error %}
    <p style="color: red;">{{ error }}</p>
    {% endif %}
    <hr>
    <p><a href="{{ url_for('logout') }}">Log Out</a></p>
</body>
</html>
'''

# --------------------------------------------------------------------
# ROUTES
# --------------------------------------------------------------------

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Allow a new user to create an account."""
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user already exists
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        existing_user = c.fetchone()

        if existing_user:
            error = "Username already taken, please choose another."
        else:
            # Create the new user with a default balance of 0
            c.execute("""
                INSERT INTO users (username, password, notes, balance)
                VALUES (?, ?, ?, ?)
            """, (username, password, '', 0.0))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        
        conn.close()

    return render_template_string(SIGNUP_TEMPLATE, error=error)


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check credentials using parameterized queries to prevent SQL injection
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            # Set session
            session['username'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password."

    return render_template_string(LOGIN_TEMPLATE, error=error)


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    """Main page after logging in, showing balance and allowing transfers."""
    # If user isn't logged in, redirect to login
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    transfer_message = None
    error = None

    # Connect to the database to get current balance
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Retrieve this user's balance
    c.execute("SELECT balance FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row:
        # If for some reason the user is missing, log them out
        conn.close()
        return redirect(url_for('logout'))
    current_balance = row[0]

    if request.method == 'POST':
        # Process a transfer to another user
        target_user = request.form['target_user']
        try:
            amount = float(request.form['amount'])
        except ValueError:
            error = "Invalid amount."
            conn.close()
            return render_template_string(DASHBOARD_TEMPLATE,
                                          username=username,
                                          balance=current_balance,
                                          transfer_message=transfer_message,
                                          error=error)

        # Check if the user has sufficient balance
        if amount <= 0:
            error = "Transfer amount must be greater than 0."
        elif amount > current_balance:
            error = "Insufficient balance."
        else:
            # Check if target user exists
            c.execute("SELECT balance FROM users WHERE username = ?", (target_user,))
            target_row = c.fetchone()
            if not target_row:
                error = f"User '{target_user}' does not exist."
            else:
                # Everything valid, proceed with the transfer
                new_balance_sender = current_balance - amount
                new_balance_target = target_row[0] + amount

                # Update balances
                c.execute("UPDATE users SET balance=? WHERE username=?", (new_balance_sender, username))
                c.execute("UPDATE users SET balance=? WHERE username=?", (new_balance_target, target_user))

                conn.commit()

                transfer_message = f"Successfully transferred {amount} to {target_user}!"
                current_balance = new_balance_sender  # Update in-memory for display

    conn.close()

    return render_template_string(DASHBOARD_TEMPLATE,
                                  username=username,
                                  balance=current_balance,
                                  transfer_message=transfer_message,
                                  error=error)


@app.route('/logout')
def logout():
    """Log out the current user."""
    session.pop('username', None)
    return redirect(url_for('login'))

# --------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------
if __name__ == '__main__':
    # Initialize the database (create table if not exists, insert admin if missing)
    init_db()
    # Run the Flask application
    app.run(host='0.0.0.0', port=5000, debug=True)
