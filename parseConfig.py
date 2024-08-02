import re
import io
import os
import itertools
import mysql.connector
from mysql.connector import errorcode
from ipaddress import IPv4Network
from dotenv import load_dotenv
from datetime import datetime
import pytz

current_time = datetime.now(pytz.timezone('Asia/Taipei')).strftime("%Y-%m-%d %H:%M:%S")
add_vlan = ("INSERT INTO vlan (fwid, vname, network, cidr, vorder) VALUES (%s, %s, %s, %s, %s)")
add_policy = ("INSERT INTO {} (fwid, vlanfrom, vlanto, userid, adminid, src, dst, service, comment, addtime, nat) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")

class Database:
    def __init__(self):
        load_dotenv()
        self.config = {
            'user': os.getenv('USER'),
            'password': os.getenv('PASSWORD'),
            'host': os.getenv('HOST'),
            'database': os.getenv('DATABASE'),
            'raise_on_warnings': True,
            'charset': 'utf8'
        }

    def __enter__(self):
        self.cnx = mysql.connector.connect(**self.config)
        self.cursor = self.cnx.cursor()
        print("DB Connection established.")
        return self.cursor

    def __exit__(self, exc_type, exc_value, traceback):
        self.cnx.commit()
        self.cursor.close()
        self.cnx.close()
        print("DB Connection has been closed.")         


class fortinet_config_parser:
    def parse_config(self, content: str, block_name: str) -> dict:
        block_reg = ''
        content_reg = ''
        group = ''
        data = {}

        match block_name:
            case 'sysintf':
                block_reg = r'(?P<sysintf>.*system\sinterface(.*\n)*?.*(?<=next\n)end)' 
                content_reg = r'(?P<intf>\".*\")(?P<set>(.*\n)*?.*next)'
                group = 'intf'
            case 'syszone':
                block_reg = r'(?P<syszone>.*system\szone(.*\n)*?.*(?<=next\n)end)'
                content_reg = r'(?P<zone>\".*\")(?P<set>(.*\n)*?.*next)'
                group = 'zone'

        for line in re.finditer(content_reg, re.search(block_reg, content).group(block_name)):
            keys = re.sub(r'\"', '', line.group(group).strip())
            data[keys] = {}
            for i in re.split(r',', re.sub(r'\n', ',', re.sub(r'.*(set\s|next|end|config\s.*)', '', line.group('set').strip()).strip())):
                attr, val = re.split(r'\s', i)[0], re.split(r'\s', i.replace('"', ''))[1:]
                data[keys][attr] = val
        return data

    def parse_firewall_policy(self, content: str) -> dict:
        fwpolicy_block_reg = r'(?P<fw>.*firewall\spolicy(.*\n)*?.*end)'
        content_reg = r'(?P<policy_id>\d+)(?P<set>(.*\n)*?.*next)'

        data = {}       
        for line in re.finditer(content_reg, re.search(fwpolicy_block_reg, content).group('fw')):
            policy_id = line.group('policy_id').strip()
            data[policy_id] = {}
            
            for i in re.split(r'\,', re.sub(r'\n', ',', re.sub(r'.*(set\s|next)', '', line.group('set').strip()))):
                attr, val = re.split(r'\s', i)[0], re.sub(r'^(\w+\s|\w+\-\w+\s)', '', i)
                if attr:
                    data[policy_id][attr] = val
        #print(data)
        return(data)

    def insert_vlan(self, db: mysql.connector.cursor, content: str, fw_name: str) -> None:
        interfcae_dict = self.parse_config(content, 'sysintf')
        zone_dict = self.parse_config(content, 'syszone')
        order = 0

        for zone, zone_attr in zone_dict.items():
            if 'interface' in zone_attr:
                for intf in zone_attr['interface']:
                    #{'vdom', 'ip'} <= (interfcae_dict[interface]).keys():
                    if intf in interfcae_dict and all(k in interfcae_dict[intf] for k in ('vdom', 'ip')):
                        #print(intf, interfcae_dict[intf]['vdom'][0], interfcae_dict[intf]['ip'])
                        order += 1
                        address, netmask = re.split(r'\/', str(IPv4Network('/'.join(ip_mask for ip_mask in interfcae_dict[intf]['ip']), False)))
                        vdom =  interfcae_dict[intf]['vdom'][0]
                        data_vlan = (fw_name, zone, address, int(netmask), order)
                        db.execute(add_vlan, data_vlan)
        print(f'Data insert into table \"vlan\" has been finished.')   

    def insert_firewall_policy(self, db: mysql.connector.cursor, content: str, fw_name: str) -> None:
        policy_dict = self.parse_firewall_policy(content)
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

        for k, v in policy_dict.items():
            if 'status' not in v or v.get('status') != 'disable':
                srcintf, dstintf = re.sub(r'\"', '', v.get('srcintf')), re.sub(r'\"', '', v.get('dstintf'))
                srcaddr = ','.join(sip for sip in re.split(r'\s', re.sub(r'\"', '', v.get('srcaddr'))))
                dstaddr = ','.join(dip for dip in re.split(r'\s', re.sub(r'\"', '', v.get('dstaddr'))))
                service = re.compile('|'.join(map(re.escape, replacements))).sub(
                    lambda match: replacements[match.group()], ','.join(
                        svc for svc in re.split(r'\s', re.sub(r'\"', '', v.get('service')))))
                #re.sub('({})'.format('|'.join(map(re.escape, replacements.keys()))), lambda m: replacements[m.group()], service)
                comments = re.sub(r'\"', '', v.get('comments')) if 'comments' in v else ''
                #print(f'{k}, {srcintf}, {dstintf}, {srcaddr}, {dstaddr}, {service}, {comments}')
                data_policy = (int(k), srcintf, dstintf, '', '', srcaddr, dstaddr, service, comments, current_time, None)
                db.execute(add_policy.format(fw_name), data_policy)
        print(f'Data insert into table \"{fw_name}\" has been finished.')
                                
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

    def parse_addrgrp(self, db: mysql.connector.cursor, content: str) -> None:
        addrgrp_reg = r'(?P<addrgrp>.*addrgrp(.*\n)*?.*end)'
        content_reg = r'(?P<grp_name>.\"\w+.*\")(?P<set>(.*\n)*?.*next)'
        data = {}

        for line in re.finditer(content_reg, re.search(addrgrp_reg, content).group('addrgrp')):
            data[re.compile(r'\"').sub('', line.group('grp_name').strip())] = re.sub(r'set\smember\s', '', line.group(3).strip())
            #data[(line.group('grp_name').replace('"', '')).strip()] = re.sub(r'set\smember\s', '', line.group(3).strip())

        print(data)
        #self.parse_firewall_address(content)
        for k,v in data.items():
            for i in (re.split(',', re.sub(r'\"\s\"', ',', v).replace('"', ''))):
                print(i)
                #TODO insert data into DB table `group` & pip install mysqldb
                #check addrgrp member in address object, if not in pass it

                #if re.match(r'^\d', i):
                    #ip, mask = re.split(r'\/', i)
                
def main():
    config_path = input("Where is your config? ")
    fw_name = input("What's your FW name? ")
    with Database() as db:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        forti = fortinet_config_parser()
        forti.insert_vlan(db, content, fw_name)
        forti.insert_firewall_policy(db, content, fw_name)

        #forti.parse_addrgrp(db, content)

        #forti.parse_firewall_address(content)
        #forti.parse_addrgrp(content)

if __name__ == "__main__":
    main()