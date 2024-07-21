import re
import io
import itertools
#import MySQLdb as musql
import getpass

#db = musql.connect(host='localhost', user='', passwd='', db='', charset='')
#cursor = db.cursor()

#def sqlExecute(sql_stat: str, val: str) -> None:
#    cursor.execute(sql_stat, val)
#    db.commit()
class configParse:
    def parseAddrgrp(path: str) -> None:
        addrgrp_reg = r'(?P<addrgrp>.*addrgrp(.*\n)*?.*end)'
        content_reg = r'(?P<grp_name>.\"\w+.*\")(?P<set>(.*\n)*?.*next)'
        with open(path, 'r', encoding='utf-8') as f:
            """
            1. named a non-capture in regex, the name is `addrgrp` by using regex `?p<namme>`.
            2, to capture `config firewall addrgrp` block in config using re.match to filter. and match will grouped in addrgrp group.
            3. parse  `edit` & `set` line and insert into DB.
            """
            data = {}
            p = re.compile(addrgrp_reg)
            for i in re.finditer(p, f.read()):
                #print(i.group('addrgrp'))
                for j in re.finditer(content_reg ,i.group('addrgrp')):
                    data[(j.group('grp_name').replace('"', '')).strip()] = re.sub(r'set\smember\s', '' ,j.group(3).strip())
            #print(data)
            for k,v in data.items():
                for v in re.split(r'\s', v.replace('"', '')):
                    if re.match(r'^\d', v):
                        ip, mask = re.split(r'\/', v)

                        #TODO insert data into DB table `group`



        
if __name__ == "__main__":
    user = input("Please give DB User name: ")
    try :
        pwd = getpass.getpass('Please give DB password: ')
    except Exception as error:
        print('ERROR', error)
    #db = musql.connect(host='localhost', user='', passwd=pwd, db='pcloudfw', charset='utf8')
    #parseAddrgrp('fw3.config')

