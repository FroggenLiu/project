import os
import json
import bcrypt
import dbsetup
import mysql.connector 

add_user_statement = ("INSERT INTO user (uid, permission, name, passwd) VALUES (%s, %s, %s, %s)")

def add_user(db: "db object"):
    for k,v in json.loads(os.getenv("USERS")).items():
        hashed = bcrypt.hashpw(v.get('password').encode(), bcrypt.gensalt())
        data = (k, '1', v.get('name'), hashed)                   
        try:
            db.execute(add_user_statement, data)
            print(f'User \"{k}\" has been created.')
        except mysql.connector.Error as e:
            print(e)

def main():
    database = dbsetup.database()
    with database as db:
        add_user(db)

if __name__ == "__main__":
    main()