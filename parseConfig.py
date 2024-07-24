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
class fortinet_config_parser:
    def parse_addrgrp(self, path: str) -> None:
        addrgrp_reg = r'(?P<addrgrp>.*addrgrp(.*\n)*?.*end)'
        content_reg = r'(?P<grp_name>.\"\w+.*\")(?P<set>(.*\n)*?.*next)'
        data = {}
        with open(path, 'r', encoding='utf-8') as f:
            for line in re.finditer(content_reg, re.search(addrgrp_reg, f.read()).group('addrgrp')):
                data[(line.group('grp_name').replace('"', '')).strip()] = re.sub(r'set\smember\s', '', line.group(3).strip())

            for k,v in data.items():
                for i in re.split(r'\s', v.replace('"', '')):
                    if re.match(r'^\d', i):
                        ip, mask = re.split(r'\/', i)
                        #TODO insert data into DB table `group` & pip install mysqldb
    
    def parse_firewall_policy(self, path: str) -> None:
        fwpolicy_block_reg = r'(?P<fw>.*firewall\spolicy(.*\n)*?.*end)'
        content_reg = r'(?P<policy_id>.edit\s\d.*)(?P<set>(.*\n)*?.*next)'

        data = {}
        replacements = {
            'ALL_TCP': 'TCP/1-65535',
            'ALL_UDP': 'UDP/1-65536',
            'ALL_ICMP': 'ICMP_ANY',
            'TCP-': 'TCP/',
            'tcp': 'TCP/',
            'UDP-': 'UDP/',
            'udp': 'UDP/',
            'TCP': 'TCP/',
            'UPD': 'UDP'
        }
        with open(path, 'r', encoding='utf-8') as f:
            for line in re.finditer(content_reg, re.search(fwpolicy_block_reg, f.read()).group('fw')):
                policy_id = re.sub(r'edit\s', '', line.group('policy_id').strip())
                data[policy_id] = {}
                for i in re.split(r'\,', re.sub(r'\n', ',', re.sub(r'(.*set\s)|.*next', '', line.group('set').strip()))):
                    set_parameter = re.split(r'\s', i)[0]
                    val = re.sub(r'^(\w+\s|\w+\-\w+\s)', '', i)
                    if set_parameter:
                        data[policy_id][set_parameter] = val

        for k, v in data.items():
            if 'status' not in v or v.get('status') != 'disable':
                #print(v.get('service'))
                srcintf = re.sub(r'\"', '', v.get('srcintf'))
                dstintf = re.sub(r'\"', '', v.get('dstintf'))
                srcaddr = ','.join(sip for sip in re.split(r'\s', re.sub(r'\"', '', v.get('srcaddr'))))
                dstaddr = ','.join(dip for dip in re.split(r'\s', re.sub(r'\"', '', v.get('dstaddr'))))
                service = re.compile(r'|'.join(map(re.escape, replacements))).sub(lambda m: replacements[m.group()], ','.join(svc for svc in re.split(r'\s', re.sub(r'\"', '', v.get('service')))))
                comments = re.sub(r'\"', '', v.get('comments')) if 'comments' in v else ''
                #print(re.sub('({})'.format('|'.join(map(re.escape, replacements.keys()))), lambda m: replacements[m.group()], service))

        
if __name__ == "__main__":
    #user = input("Please give DB User name: ")
    #try :
    #    pwd = getpass.getpass('Please give DB password: ')
    #except Exception as error:
    #    print('ERROR', error)
    #db = musql.connect(host='localhost', user='', passwd=pwd, db='pcloudfw', charset='utf8')
    sol = fortinet_config_parser()
    #sol.parse_addrgrp('FW3.conf')
    sol.parse_firewall_policy('FW3.conf')