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

    def parse_system_interface(self, content: str) -> None:
        #Lookaheads and Lookbehinds
        system_interface_block_reg = r'(?P<sysintf>.*system\sinterface(.*\n)*?.*(?<=next\n)end)' 
        content_reg = r'(?P<intf>\".*\")(?P<set>(.*\n)*?.*next)'
        data = {}
        for line in re.finditer(content_reg, re.search(system_interface_block_reg, content).group('sysintf')):
            intf = re.sub(r'\"', '', line.group('intf').strip())
            data[intf] = {}
            for i in re.split(r',', re.sub(r'\n', ',', re.sub(r'.*(set\s|next|end|config\s.*)', '', line.group('set').strip()).strip())):
                attr, val = re.split(r'\s', i)[0], re.split(r'\s', i)[1:]
                data[intf][attr] = val
        print(data)

    def parse_firewall_address(self, content: str) -> dict:
        fwaddress_block_reg = r'(?P<addr>.*firewall\saddress(.*\n)*?.*end\n)'
        content_reg = r'(?P<address_name>\".*\")(?P<set>(.*\n)*?.*next)'
        data = {}
        for line in re.finditer(content_reg, re.search(fwaddress_block_reg, content).group('addr')):
            address_obj_name = re.sub(r'\"', '', line.group('address_name').strip())
            data[address_obj_name] = {}
            for i in re.split(r',', re.sub(r'\n', ',', (re.sub(r'.*(set\s|next)', '', line.group('set').strip())).strip())):
                attr, val = re.split(r'\s', i)[0], re.split(r'\s', i)[1:]
                data[address_obj_name][attr] = val
        #print(data)
        return data


    def parse_addrgrp(self, content: str) -> None:
        addrgrp_reg = r'(?P<addrgrp>.*addrgrp(.*\n)*?.*end)'
        content_reg = r'(?P<grp_name>.\"\w+.*\")(?P<set>(.*\n)*?.*next)'
        data = {}
        #with open(path, 'r', encoding='utf-8') as f:
        for line in re.finditer(content_reg, re.search(addrgrp_reg, content).group('addrgrp')):
            data[re.compile(r'\"').sub('', line.group('grp_name').strip())] = re.sub(r'set\smember\s', '', line.group(3).strip())
            #data[(line.group('grp_name').replace('"', '')).strip()] = re.sub(r'set\smember\s', '', line.group(3).strip())

        #print(data)
        #self.parse_firewall_address(content)
        for k,v in data.items():
            for i in (re.split(',', re.sub(r'\"\s\"', ',', v).replace('"', ''))):
                print(i)
                #TODO insert data into DB table `group` & pip install mysqldb
                #check addrgrp member in address object, if not in pass it

                #if re.match(r'^\d', i):
                    #ip, mask = re.split(r'\/', i)


    def parse_firewall_policy(self, content: str) -> None:
        fwpolicy_block_reg = r'(?P<fw>.*firewall\spolicy(.*\n)*?.*end)'
        content_reg = r'(?P<policy_id>\d+)(?P<set>(.*\n)*?.*next)'

        data = {}
        replacements = {
            'ALL_TCP': 'TCP/1-65535',
            'ALL_UDP': 'UDP/1-65535',
            'ALL_ICMP': 'ICMP_ANY',
            'TCP-': 'TCP/',
            'tcp': 'TCP/',
            'UDP-': 'UDP/',
            'udp': 'UDP/',
            'TCP': 'TCP/',
            'UPD': 'UDP',
        }

        #with open(path, 'r', encoding='utf-8') as f:        
        for line in re.finditer(content_reg, re.search(fwpolicy_block_reg, content).group('fw')):
            policy_id = line.group('policy_id').strip()
            data[policy_id] = {}
            
            for i in re.split(r'\,', re.sub(r'\n', ',', re.sub(r'.*(set\s|next)', '', line.group('set').strip()))):
                attr, val = re.split(r'\s', i)[0], re.sub(r'^(\w+\s|\w+\-\w+\s)', '', i)
                if attr:
                    data[policy_id][attr] = val
        #print(data)
        for k, v in data.items():
            if 'status' not in v or v.get('status') != 'disable':
                srcintf = re.sub(r'\"', '', v.get('srcintf'))
                dstintf = re.sub(r'\"', '', v.get('dstintf'))
                srcaddr = ','.join(sip for sip in re.split(r'\s', re.sub(r'\"', '', v.get('srcaddr'))))
                dstaddr = ','.join(dip for dip in re.split(r'\s', re.sub(r'\"', '', v.get('dstaddr'))))
                service = re.compile('|'.join(map(re.escape, replacements))).sub(
                    lambda match: replacements[match.group()], ','.join(
                        svc for svc in re.split(r'\s', re.sub(r'\"', '', v.get('service')))))
                #re.sub('({})'.format('|'.join(map(re.escape, replacements.keys()))), lambda m: replacements[m.group()], service)
                comments = re.sub(r'\"', '', v.get('comments')) if 'comments' in v else ''
                print(f'{k}, {srcintf}, {dstintf}, {srcaddr}, {dstaddr}, {service}, {comments}')
                #TODO insert data into DB & pip install mysqldb

def main():
    #user = input("Please give DB User name: ")
    #try :
    #    pwd = getpass.getpass('Please give DB password: ')
    #except Exception as error:
    #    print('ERROR', error)
    #db = musql.connect(host='localhost', user='', passwd=pwd, db='pcloudfw', charset='utf8')
    sol = fortinet_config_parser()
    with open('FW1.conf', 'r', encoding='utf-8') as f:
        content = f.read()
    #sol.parse_firewall_address(content)
    sol.parse_system_interface(content)
    #sol.parse_addrgrp(content)
    #sol.parse_firewall_policy(content)


if __name__ == "__main__":
    main()