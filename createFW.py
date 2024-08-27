import os
import json
import bcrypt
import dbsetup
import mysql.connector 

add_fw_statement = ("INSERT INTO fwinfo (fwid, vdom, name, ip, account, pw, ftype, chtdeip) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")
create_table_statment = (
    "CREATE TABLE {} (`fwid` int(10) NOT NULL AUTO_INCREMENT PRIMARY KEY, `vlanfrom` varchar(50) NOT NULL, `vlanto` varchar(50) NOT NULL,"
    "`userid` varchar(50) NOT NULL, `adminid` varchar(50) NOT NULL, `src` text NOT NULL, `dst` text NOT NULL, `service` text NOT NULL,"
    "`comment` longtext NOT NULL, `addtime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, `nat` varchar(50)) ENGINE=InnoDB"
    )

def add_fw_info(db: "db object"):
    for k, v in json.loads(os.getenv("FW")).items():
        hashed = bcrypt.hashpw(v.get('password').encode(), bcrypt.gensalt())
        data = (k, v.get('vdom'), v.get('name'), v.get('ip'), v.get('account'), hashed, '0', v.get('chtdeip'))
        try:
            db.execute(add_fw_statement, data)
            print(f'FW \"{k}\" info has been added.')
            db.execute(create_table_statment.format(k))
            print(f'Table \"{k}\" has been created.')
        except mysql.connector.Error as e:
            print(e)

def main():
    database = dbsetup.database()
    with database as db:
        add_fw_info(db)

if __name__ == "__main__":
    main()