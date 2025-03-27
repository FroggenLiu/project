import mysql.connector
import os
from typing import Optional
from dotenv import load_dotenv
from mysql.connector import Error
from mysql.connector.pooling import MySQLConnectionPool

class Database:
    """Database connection manager with connection pooling"""
    
    _instance: Optional['Database'] = None
    _pool: Optional[MySQLConnectionPool] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            cls._instance._initialize()
            
        return cls._instance
    
    def _initialize(self):
        """Initialize database connection pool"""
        load_dotenv()
        self.config = {
            'user': os.getenv('DBUSER'),
            'password': os.getenv('PASSWORD'),
            'host': os.getenv('HOST'),
            'database': os.getenv('DATABASE'),
            'raise_on_warnings': True,
            'charset': 'utf8',
            'pool_name': 'mypool',
            'pool_size': 5
        }
        
        try:
            self._pool = MySQLConnectionPool(**self.config)
        except Error as e:
            print(f"Error creating connection pool: {e}")
            raise

    def __enter__(self):
        """Get a connection from the pool"""
        try:
            self.connection = self._pool.get_connection()
            self.cursor = self.connection.cursor()
            print("DB Connection established from pool.")
            return self.cursor
        except Error as e:
            print(f"Error getting connection from pool: {e}")
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        """Return connection to pool and handle cleanup"""
        try:
            if hasattr(self, 'cursor') and self.cursor:
                self.cursor.close()
            if hasattr(self, 'connection') and self.connection:
                if exc_type is None:  # No exception occurred
                    self.connection.commit()
                else:  # Exception occurred
                    self.connection.rollback()
                self.connection.close()
            print("DB Connection returned to pool.")
        except Error as e:
            print(f"Error closing connection: {e}")
            raise        
