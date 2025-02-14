import sqlite3
import bcrypt  # <-- ADD THIS

class DatabaseManager:
    def __init__(self, db_path='users.db'):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize the SQLite database and create tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                notes TEXT,
                balance REAL
            )
        ''')

        # Insert a default admin with hashed password if not exists
        admin_password = "a1d2m3I4n5!@#"
        hashed_admin_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        c.execute('''
            INSERT OR IGNORE INTO users (username, password, notes, balance)
            VALUES (?, ?, ?, ?)
        ''', ('admin', hashed_admin_password, 'Secret admin notes', 10000000.0))

        conn.commit()
        conn.close()

    def get_user(self, username):
        """Return user row as a tuple (username, password, notes, balance) or None."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_row = c.fetchone()
        conn.close()
        return user_row

    def create_user(self, username, hashed_password):
        """Insert a new user with zero balance by default."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO users (username, password, notes, balance)
            VALUES (?, ?, ?, ?)
        """, (username, hashed_password, '', 0.0))
        conn.commit()
        conn.close()

    def validate_credentials(self, username, password):
        """
        Check if credentials are valid.
        Return user tuple if valid, else None.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user:
            stored_hashed_password = user[1]  # hashed password in DB
            # Compare given password (hashed) with stored hashed password
            if bcrypt.hashpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')) == stored_hashed_password.encode('utf-8'):
                return user

        # If user doesn't exist or password didn't match
        return None

    def update_balance(self, username, new_balance):
        """Update a user's balance."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE users SET balance = ? WHERE username = ?", (new_balance, username))
        conn.commit()
        conn.close()

    def user_exists(self, username):
        """Check if a user with the given username already exists."""
        return self.get_user(username) is not None
