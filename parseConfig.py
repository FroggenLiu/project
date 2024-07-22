import re
import io
import itertools
#import MySQLdb as musql
import getpass
import ipaddress

#db = musql.connect(host='localhost', user='', passwd='', db='', charset='')
#cursor = db.cursor()

#def sqlExecute(sql_stat: str, val: str) -> None:
#    cursor.execute(sql_stat, val)
#    db.commit()
class configParse:
    def parse_addrgrp(self, path: str) -> None:
        addrgrp_reg = r'(?P<addrgrp>.*addrgrp(.*\n)*?.*end)'
        content_reg = r'(?P<grp_name>.\"\w+.*\")(?P<set>(.*\n)*?.*next)'
        data = {}
        with open(path, 'r', encoding='utf-8') as f:
            """
            1. named a non-capture in regex, the name is `addrgrp` by using regex `?p<namme>`.
            2, to capture `config firewall addrgrp` block in config using re.match to filter. and match will grouped in addrgrp group.
            3. parse  `edit` & `set` line and insert into DB.
            """
            #p = re.compile(addrgrp_reg)
            for i in re.finditer(content_reg, re.search(addrgrp_reg, f.read()).group('addrgrp')):
                data[(i.group('grp_name').replace('"', '')).strip()] = re.sub(r'set\smember\s', '', i.group(3).strip())
            #print(data)
            for k,v in data.items():
                for v in re.split(r'\s', v.replace('"', '')):
                    if re.match(r'^\d', v):
                        ip, mask = re.split(r'\/', v)
                        #TODO insert data into DB table `group` & pip install mysqldb
    
    def parse_firewall_policy(self, path: str) -> None:
        fwpolicy_reg = r'(?P<fw>.*firewall\spolicy(.*\n)*?.*end)'
        content_reg = r'(?P<policy_id>.edit\s\d.*)(?P<set>(.*\n)*?.*next)'
        data = {}
        with open(path, 'r', encoding='utf-8') as f:
            for i in re.finditer(content_reg, re.search(fwpolicy_reg, f.read()).group('fw')):
                data[re.sub(r'edit\s', '', i.group('policy_id').strip())] = re.sub(r'\n', ',', re.sub(r'(.*set\s)|.*next', '', i.group('set').strip()))
                #print(re.sub(r'\n', ',', re.sub(r'(.*set\s)|.*next', '', i.group('set').strip())))
                #data[re.sub(r'edit\s', i.group('policy_id').strip())]
        print(data)
                

            


        
if __name__ == "__main__":
    #user = input("Please give DB User name: ")
    #try :
    #    pwd = getpass.getpass('Please give DB password: ')
    #except Exception as error:
    #    print('ERROR', error)
    #db = musql.connect(host='localhost', user='', passwd=pwd, db='pcloudfw', charset='utf8')
    sol = configParse()
    sol.parse_firewall_policy('FW3.config')

