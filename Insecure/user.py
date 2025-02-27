# user.py

class User:
    """Represents an application user."""
    def __init__(self, username, password, notes="", balance=0.0):
        self.username = username
        self.password = password
        self.notes = notes
        self.balance = balance

    def deposit(self, amount):
        """Increase user balance (in-memory)."""
        if amount > 0:
            self.balance += amount

    def withdraw(self, amount):
        """Decrease user balance (in-memory)."""
        if amount > 0 and amount <= self.balance:
            self.balance -= amount
