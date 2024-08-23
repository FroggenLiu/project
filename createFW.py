import os
import json
import bcrypt
import dbsetup
import mysql.connector 

add_fw = ("INSERT INTO fwinfo (fwid, vdom, name, ip, account, pw, ftype, chtdeip) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")
create_table = ("CREATE TABLE {} SELECT * FROM FW3 WHERE 1 = 0")


def add_fw_info(db: "db object"):
    for k, v in json.loads(os.getenv("FW")).items():
        hashed = bcrypt.hashpw(v['password'].encode(), bcrypt.gensalt())
        data = (k, v['vdom'], v['name'], v['ip'], v['account'], hashed, '0', None)
        try:
            db.execute(add_fw, data)
            print(f'FW \"{k}\" info has been added.')
            create_fw_table(db, k)
        except mysql.connector.Error as e:
            print(e)

def create_fw_table(db: "db object", fw_name: str):
    try:
        db.execute(create_table.format(fw_name))
        print(f'Table \"{fw_name}\" has been created.')
    except mysql.connector.Error as e:
        print(e)

def main():
    database = dbsetup.database()
    with database as db:
        add_fw_info(db)

if __name__ == "__main__":
    main()