import os
import re
import json
import dbsetup
import mysql.connector

del_statment = ("DELETE FROM {} WHERE (fwid, vdom) IN ((\'{}\',\'{}\'))")
get_fw_statemnet = ("SELECT vdom FROM fwinfo WHERE fwid=\'{}\'")
drop_table_statment = ("DROP TABLE {}")

def del_all(db: 'db object', fw_name: str) -> None:
    try:
        db.execute(get_fw_statemnet.format(fw_name))
        for [vd] in db:
            for k in ('vlan', 'fwinfo'): 
                print(f'Executing sql command: \"{del_statment.format(k, fw_name, vd)}\"')
                db.execute(del_statment.format(k, fw_name, vd))
            print(f'Executing sql command: \"{drop_table_statment.format(fw_name)}\"')
            db.execute(drop_table_statment.format(fw_name))      
    except mysql.connector.Error as e:
        print(e)


def main():
    database = dbsetup.database()
    for k,v in json.loads(os.getenv('FW')).items():
        with database as db:
            del_all(db, k)
        print(f'Delete FW {k} is finidhed.\n')

if __name__ == "__main__":
    main()