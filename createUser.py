import bcrypt
import mysql.connector
import os
import json
from dotenv import load_dotenv

add_user = ("INSERT INTO user (uid, permission, name, passwd) VALUES (%s, %s, %s, %s)")

class database:
    def __init__(self):
        load_dotenv()
        self.config = {
            'user': os.getenv('USER'),
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

def main():
    load_dotenv()
    with database() as db:
        for k,v in json.loads(os.getenv("USERS")).items():
            hashed = bcrypt.hashpw(v[1].encode(), bcrypt.gensalt())
            data = (k, '1', v[0], hashed)
            db.execute(add_user, data)

if __name__ == "__main__":
    main()