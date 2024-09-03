import os
import re
import json
import dbsetup
import mysql.connector
from collections import defaultdict
from ipaddress import IPv4Network


get_fw_statemnet = ("SELECT vdom FROM fwinfo WHERE fwid=\'{}\'")
del_vlan_statment = ("DELETE FROM vlan WHERE (fwid, vdom) IN ((\'{}\',\'{}\'))")
add_vlan_statement = ("INSERT INTO vlan (fwid, vdom, vname, network, cidr, vorder) VALUES (%s, %s, %s, %s, %s, %s)")


def parse_config(content: str, block_name: str, *args) -> dict:
        block_reg = ''
        content_reg = ''
        group = ''
        data = defaultdict(dict)
        contents = ''

        match block_name:
            case 'sysintf':
                block_reg = r'(?P<sysintf>.*system\sinterface(.*\n)*?.*(?<=next\n)end)' 
                content_reg = r'(?P<intf>\".*\")(?P<set>(.*\n)*?.*next)'
                group = 'intf'
                contents = content
            case 'syszone':
                block_reg = r'(?P<syszone>.*system\szone(.*\n)*?.*(?<=next\n)end)'
                content_reg = r'(?P<zone>\".*\")(?P<set>(.*\n)*?.*next)'
                contents = re.search(r'(?P<vdom>(config\svdom\sedit\s{})(.*\n)*?end\nend)'.format(*args), content).group('vdom')
                group = 'zone'
    
        if re.search(block_reg, contents) is not None :
            for line in re.finditer(content_reg, re.search(block_reg, contents).group(block_name)):
                keys = re.sub(r'\"', '', line.group(group).strip())
                for i in re.split(r',', re.sub(r'\n', ',', re.sub(r'.*(set\s|next|end|config\s.*)', '', line.group('set').strip()).strip())):
                    attr, val = re.split(r'\s', i)[0], re.split(r'\s', i.replace('"', ''))[1:]
                    data[keys][attr] = val
            return data
        else:
            return False


def insert_vlan(db: 'db object', content: str, fw_name: str, vdom_name: str, default_zone: str) -> None:
    interfcae_dict = parse_config(content, 'sysintf')
    zone_dict = parse_config(content, 'syszone', vdom_name)
    order = 0
    
    if not zone_dict:
        print(f'No ZONE config in vdom \"{vdom_name}\"')
    else:
        for zone, zone_attr in zone_dict.items():
            if 'interface' in zone_attr:
                for intf in zone_attr['interface']:
                    if intf in interfcae_dict and all(k in interfcae_dict[intf] for k in ('vdom', 'ip')):
                        order += 1
                        address, netmask = re.split(r'\/', str(IPv4Network('/'.join(ip_mask for ip_mask in interfcae_dict[intf]['ip']), False)))
                        vdom =  interfcae_dict[intf]['vdom'][0]
                        data_vlan = (fw_name, vdom, zone, address, int(netmask), order)
                        try:
                            db.execute(add_vlan_statement, data_vlan)
                        except mysql.connector.Error as e:
                            print(e)
                        
        print(f'Data insert into table \"vlan\" is finished.')

    order += 1
    default = (fw_name, vdom_name, default_zone, '0.0.0.0', '0', order)
    try:
        db.execute(add_vlan_statement, default) 
        print(f'Add default vlan into table \"vlan\" is finished.') 
    except mysql.connector.Error as e:
        print(e)


def modify_zone(db: 'db object', content: str, fw_name: str, default_zone_name: str) -> None:
    try:
        db.execute(get_fw_statemnet.format(fw_name))
        for [vd] in db:
            db.execute(del_vlan_statment.format(fw_name, vd))
            print(f'Delete \"{fw_name}\" data in table `vlan` is finished.')
            insert_vlan(db, content, fw_name, vd, default_zone_name)
    except mysql.connector.Error as e:
        print(e)


def main():
    database = dbsetup.database()
    for k,v in json.loads(os.getenv('FW')).items():
        fw_name, config_path, default_zone_name = k, v.get('config'), v.get('default_zone')
        print(fw_name, config_path, default_zone_name)
        with database as db:
            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()
            modify_zone(db, content, fw_name, default_zone_name)

if __name__ == "__main__":
    main()