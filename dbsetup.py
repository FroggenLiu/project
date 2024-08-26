import mysql.connector
import os
from dotenv import load_dotenv

class database:
    def __init__(self):
        load_dotenv()
        self.config = {
            'user': os.getenv('DBUSER'),
            'password': os.getenv('PASSWORD'),
            'host': os.getenv('HOST'),
            'database': os.getenv('DATABASE'),
            'raise_on_warnings': True,
            'charset': 'utf8'
        }

    def __enter__(self):
        self.cnx = mysql.connector.connect(**self.config)
        self.cursor = self.cnx.cursor()
        print("DB Connection established.")
        return self.cursor

    def __exit__(self, exc_type, exc_value, traceback):
        self.cnx.commit()
        self.cursor.close()
        self.cnx.close()
        print("DB Connection has been closed.")        
