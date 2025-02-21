import sqlite3
import bcrypt
import time
class DatabaseManager:
    def __init__(self, db_path='users.db'):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """
        Initialize the SQLite database and create the 'users' table if it doesn't exist.
        Also inserts a default admin user with a hashed password if not present.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        # Create table if it doesn't exist
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                notes TEXT,
                balance REAL
            )
        ''')

        # Insert a default admin user with a hashed password if not exists
        admin_password = "a1d2m3I4n5!@#"  # Example admin password
        hashed_admin_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        c.execute('''
            INSERT OR IGNORE INTO users (username, password, notes, balance)
            VALUES (?, ?, ?, ?)
        ''', ('admin', hashed_admin_password, 'Secret admin notes', 10000000.0))

        conn.commit()
        conn.close()

    def get_user(self, username):
        """
        Return user row as a tuple (username, password, notes, balance)
        or None if user doesn't exist.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_row = c.fetchone()
        conn.close()
        return user_row

    def create_user(self, username, hashed_password):
        """
        Insert a new user with hashed password, empty notes, and zero balance.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO users (username, password, notes, balance)
            VALUES (?, ?, ?, ?)
        """, (username, hashed_password, '', 0.0))
        conn.commit()
        conn.close()

   

    def validate_credentials(username, password):
        user_row = db_manager.get_user(username)
        if user_row:
            stored_hashed_password = user_row[1]
            if bcrypt.hashpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')) == stored_hashed_password.encode('utf-8'):
                return user_row
        time.sleep(2)  # Delay brute-force attempts
        return None


    def update_balance(self, username, new_balance):
        """
        Update a user's balance in the database.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE users SET balance = ? WHERE username = ?", (new_balance, username))
        conn.commit()
        conn.close()

    def user_exists(self, username):
        """
        Check if a user with the given username already exists.
        """
        return self.get_user(username) is not None
