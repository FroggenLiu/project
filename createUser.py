import os
import json
import bcrypt
import dbsetup
import mysql.connector 

add_user = ("INSERT INTO user (uid, permission, name, passwd) VALUES (%s, %s, %s, %s)")

def add_user(db: "db object"):
    for k,v in json.loads(os.getenv("USERS")).items():
        hashed = bcrypt.hashpw(v[1].encode(), bcrypt.gensalt())
        data = (k, '1', v[0], hashed)                   
        try:
            db.execute(add_user, data)
            print(f'User \"{k}\" has been insert into database table \'user\'.')
        except mysql.connector.Error as e:
            print(e)

def main():
    database = dbsetup.database()
    with database as db:
        add_user(db)

if __name__ == "__main__":
    main()