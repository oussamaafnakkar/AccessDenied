"""
Database operations (vulnerable to SQL injection)
"""

import sqlite3
import os

class Database:
    def __init__(self, db_path="securebank.db"):
        self.db_path = db_path
    
    def init_database(self):
        """Initialize database with sample data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Customers table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY,
                name TEXT,
                email TEXT,
                account_balance REAL,
                ssn TEXT
            )
        """)
        
        # Admin tokens table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_tokens (
                token TEXT PRIMARY KEY,
                description TEXT
            )
        """)
        
        # Insert sample data
        cursor.execute("""
            INSERT OR REPLACE INTO customers VALUES
            (1, 'John Doe', 'john@example.com', 50000.00, '123-45-6789'),
            (2, 'Jane Smith', 'jane@example.com', 75000.00, '987-65-4321'),
            (3, 'Bob Johnson', 'bob@example.com', 120000.00, '555-12-3456')
        """)
        
        # Insert admin token (discoverable for CTF)
        cursor.execute("""
            INSERT OR REPLACE INTO admin_tokens VALUES
            ('admin_token_12345', 'Admin access token')
        """)
        
        conn.commit()
        conn.close()
        
        print("[DATABASE] Initialized with sample data")
    
    def execute_query(self, query: str):
        """
        Execute SQL query (VULNERABLE TO SQL INJECTION)
        
        In real app, would use parameterized queries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Vulnerability: Direct SQL execution
            cursor.execute(query)
            results = cursor.fetchall()
            conn.close()
            return results
        except Exception as e:
            conn.close()
            return f"Error: {e}"
    
    def verify_admin_token(self, token: str) -> bool:
        """Verify admin token"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM admin_tokens WHERE token = ?", (token,))
        result = cursor.fetchone()
        
        conn.close()
        return result is not None
