import os
import json
import bcrypt
import dbsetup

add_user = ("INSERT INTO user (uid, permission, name, passwd) VALUES (%s, %s, %s, %s)")
      
def main():
    database = dbsetup.database()
    with database as db:
        for k,v in json.loads(os.getenv("USERS")).items():
            hashed = bcrypt.hashpw(v[1].encode(), bcrypt.gensalt())
            data = (k, '1', v[0], hashed)
            print(f'User \"{k}\" has been insert into database table \'user\'.')
            db.execute(add_user, data)

if __name__ == "__main__":
    main()