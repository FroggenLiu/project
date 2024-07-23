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
                for i in re.split(r'\s', v.replace('"', '')):
                    if re.match(r'^\d', i):
                        ip, mask = re.split(r'\/', i)
                        #TODO insert data into DB table `group` & pip install mysqldb
    
    def parse_firewall_policy(self, path: str) -> None:
        fwpolicy_block_reg = r'(?P<fw>.*firewall\spolicy(.*\n)*?.*end)'
        content_reg = r'(?P<policy_id>.edit\s\d.*)(?P<set>(.*\n)*?.*next)'
        replace_set_next_reg = r'(.*set\s)|.*next'
        replace_edit_reg = r'edit\s'
        replace_prefix_reg = r'^(\w+\s|\w+\-\w+\s)'
        split_space_reg = r'\s'
        split_comma_reg = r'\,'
        split_scape_reg = r'\n'

        data = {}
        with open(path, 'r', encoding='utf-8') as f:
            for id in re.finditer(content_reg, re.search(fwpolicy_block_reg, f.read()).group('fw')):
                data[re.sub(replace_edit_reg, '', id.group('policy_id').strip())] = {}
                for line in re.split(split_comma_reg, re.sub(split_scape_reg, ',', re.sub(replace_set_next_reg, '', id.group('set').strip()))):
                    if re.split(split_space_reg, line)[0]:
                        data[re.sub(replace_edit_reg, '', id.group('policy_id').strip())][re.split(split_space_reg, line)[0]] = re.sub(replace_prefix_reg, '', line)
            print(data)
    
                 
        
if __name__ == "__main__":
    #user = input("Please give DB User name: ")
    #try :
    #    pwd = getpass.getpass('Please give DB password: ')
    #except Exception as error:
    #    print('ERROR', error)
    #db = musql.connect(host='localhost', user='', passwd=pwd, db='pcloudfw', charset='utf8')
    sol = configParse()
    #sol.parse_addrgrp('FW3.conf')
    sol.parse_firewall_policy('FW3.conf')
    
    

