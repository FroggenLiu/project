import re
import io
import os
import pytz
import bcrypt
import dbsetup
import itertools
import json
import logging
import mysql.connector
from abc import ABC, abstractmethod
from ipaddress import IPv4Network
from dotenv import load_dotenv
from datetime import datetime
from collections import defaultdict
from typing import Dict, Any, Optional
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall_parser.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Database statements
class DBStatements:
    """Database SQL statements"""
    ADD_VLAN = ("INSERT INTO vlan (fwid, vdom, vname, network, cidr, vorder) VALUES (%s, %s, %s, %s, %s, %s)")
    ADD_POLICY = ("INSERT INTO {} (fwid, vlanfrom, vlanto, userid, adminid, src, dst, service, comment, addtime, nat) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
    ADD_FW = ("INSERT INTO fwinfo (fwid, vdom, name, ip, account, pw, ftype, chtdeip) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")
    CREATE_FW_TABLE = (
        "CREATE TABLE {} (`fwid` int(10) NOT NULL AUTO_INCREMENT PRIMARY KEY, `vlanfrom` varchar(50) NOT NULL, `vlanto` varchar(50) NOT NULL,"
        "`userid` varchar(50) NOT NULL, `adminid` varchar(50) NOT NULL, `src` text NOT NULL, `dst` text NOT NULL, `service` text NOT NULL,"
        "`comment` longtext, `addtime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, `nat` varchar(50)) ENGINE=InnoDB"
    )
    DEL_VLAN = ("DELETE FROM vlan WHERE (fwid, vdom) IN ((\'{}\',\'{}\'))")
    SHOW_TABLES = ("SHOW TABLES LIKE \'{}\'")
    GET_FW_INFO = ("SELECT \'fwid\' FROM \'fwinfo\' WHERE fwid=\'{}\'")
    GET_POLICY = ("SELECT * FROM {}")
    UPDATE_POLICY = ("UPDATE {} SET vlanfrom=\'{}\', vlanto=\'{}\', src=\'{}\', dst=\'{}\', service=\'{}\' WHERE fwid=\'{}\'")
    DEL_POLICY = ("DELETE FROM {} WHERE `fwid`=\'{}\'")

class ConfigError(Exception):
    """Custom exception for configuration errors"""
    pass

class Firewall(ABC):
    """Abstract base class for all firewall types"""
    
    def __init__(self, fw_name: str, config_path: str, config: Dict[str, Any]):
        """
        Initialize firewall with basic parameters
        Args:
            fw_name: Name of the firewall
            config_path: Path to the config file
            config: Dictionary containing firewall-specific configuration
        """
        self.fw_name = fw_name
        self.config_path = config_path
        self.config = config
        self._validate_config()

    @abstractmethod
    def _validate_config(self) -> None:
        """Validate firewall-specific configuration"""
        pass

    @abstractmethod
    def parse_config(self, content: str, block_name: str, *args) -> Dict[str, Any]:
        """Parse configuration blocks from firewall config"""
        pass

    @abstractmethod
    def parse_firewall_policy(self, content: str) -> Dict[str, Any]:
        """Parse firewall policies from config"""
        pass

    @abstractmethod
    def insert_vlan(self, db: mysql.connector.cursor, content: str) -> None:
        """Insert VLAN information into database"""
        pass

    @abstractmethod
    def insert_firewall_policy(self, db: mysql.connector.cursor, content: str, *fwinfo) -> None:
        """Insert firewall policies into database"""
        pass

    @abstractmethod
    def parse_firewall_address(self, content: str) -> Dict[str, Any]:
        """Parse firewall address objects from config"""
        pass

    @abstractmethod
    def parse_addrgrp(self, db: mysql.connector.cursor, content: str) -> None:
        """Parse address groups from config"""
        pass

    @abstractmethod
    def resync_fw_policy(self, db: mysql.connector.cursor, content: str) -> None:
        """Resynchronize firewall policies with database"""
        pass

class FortinetFirewall(Firewall):
    """Fortinet specific firewall implementation"""
    
    def __init__(self, fw_name: str, config_path: str, config: Dict[str, Any]):
        """
        Initialize Fortinet firewall
        Args:
            fw_name: Name of the firewall
            config_path: Path to the config file
            config: Dictionary containing:
                - vdom_name: VDOM name
                - default_zone_name: Default zone name
        """
        super().__init__(fw_name, config_path, config)
        self.vdom_name = config.get('vdom_name', '')
        self.default_zone_name = config.get('default_zone_name', '')
    
    def _validate_config(self) -> None:
        """Validate Fortinet-specific configuration"""
        if not self.vdom_name:
            raise ConfigError("VDOM name is required for Fortinet firewalls")
        if not self.default_zone_name:
            raise ConfigError("Default zone name is required for Fortinet firewalls")

    def parse_config(self, content: str, block_name: str, *args) -> dict:
        block_reg = ''
        content_reg = ''
        group = ''
        data = defaultdict(dict)

        match block_name:
            case 'sysintf':
                block_reg = r'(?P<sysintf>.*system\sinterface(.*\n)*?end)'  
                content_reg = r'(?P<intf>\".*\")(?P<set>(.*\n)*?.*next)'
                group = 'intf'
            case 'syszone':
                block_reg = r'(?P<syszone>.*system\szone(.*\n)*?end)'
                content_reg = r'(?P<zone>\".*\")(?P<set>(.*\n)*?.*next)'
                content = re.search(r'(?P<vdom>(config\svdom\sedit\s{})(.*\n)*?end\nend)'.format(self.vdom_name), content).group('vdom') if len(re.findall(r'.*system\szone', content)) > 1 else content
                group = 'zone'

        if re.search(block_reg, content) is not None:
            for line in re.finditer(content_reg, re.search(block_reg, content).group(block_name)):
                keys = re.sub(r'\"', '', line.group(group).strip())
                for i in re.split(r',', re.sub(r'\n', ',', re.sub(r'.*(set\s|next|end|config\s.*)', '', line.group('set').strip()).strip())):
                    attr, val = re.split(r'\s', i)[0], re.split(r'\s', i.replace('"', ''))[1:]
                    data[keys][attr] = val
            return data
        else:
            return False

    def parse_firewall_policy(self, content: str) -> dict:
        fwpolicy_block_reg = r'(?P<fw>.*firewall\spolicy(.*\n)*?end)'
        content_reg = r'(?P<policy_id>\d+)(?P<set>(.*\n)*?.*next)'
        data = defaultdict(dict)

        content = re.search(r'(?P<vdom>(config\svdom\sedit\s{})(.*\n)*?end\nend)'.format(self.vdom_name), content).group('vdom') if len(re.findall(r'.*firewall\spolicy', content)) > 1 else content

        for line in re.finditer(content_reg, re.search(fwpolicy_block_reg, content).group('fw')):
            policy_id = line.group('policy_id').strip()
            for i in re.split(r'\,', re.sub(r'\n', ',', re.sub(r'.*(set\s|next)', '', line.group('set').strip()))):
                attr, val = re.split(r'\s', i)[0], re.sub(r'^(\w+\s|\w+\-\w+\s)', '', i)
                if attr:
                    data[policy_id][attr] = val
        return data

    def insert_vlan(self, db: mysql.connector.cursor, content: str) -> None:
        interfcae_dict = self.parse_config(content, 'sysintf')
        zone_dict = self.parse_config(content, 'syszone')
        order = 0
        
        try:
            db.execute(DBStatements.DEL_VLAN.format(self.fw_name, self.vdom_name))
        except mysql.connector.Error as e:
            print(e)

        if not zone_dict:
            print(f'No ZONE config in vdom \"{self.vdom_name}\"')
        else:
            for zone, zone_attr in zone_dict.items():
                if 'interface' in zone_attr:
                    for intf in zone_attr['interface']:
                        if intf in interfcae_dict and all(k in interfcae_dict[intf] for k in ('vdom', 'ip')):
                            order += 1
                            address, netmask = re.split(r'\/', str(IPv4Network('/'.join(ip_mask for ip_mask in interfcae_dict[intf]['ip']), False)))
                            vdom = interfcae_dict[intf]['vdom'][0]
                            data_vlan = (self.fw_name, vdom, zone, address, int(netmask), order)
                            try:
                                db.execute(DBStatements.ADD_VLAN, data_vlan)
                            except mysql.connector.Error as e:
                                print(e)
            print(f'Data insert into table \"vlan\" is finished.')
         
        order += 1
        default = (self.fw_name, self.vdom_name, self.default_zone_name, '0.0.0.0', '0', order)
        try:
            db.execute(DBStatements.ADD_VLAN, default)
            print(f'Add default vlan into table \"vlan\" is finished.')
        except mysql.connector.Error as e:
            print(e)

    def insert_firewall_policy(self, db: mysql.connector.cursor, content: str, *fwinfo) -> None:
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

        try:
            db.execute(DBStatements.SHOW_TABLES.format(self.fw_name))
            if not db.fetchone():
                db.execute(DBStatements.CREATE_FW_TABLE.format(self.fw_name))
                db.execute(DBStatements.GET_FW_INFO.format(self.fw_name))
                if not db.fetchone():
                    db.execute(DBStatements.ADD_FW, *fwinfo)
        except mysql.connector.Error as e:
            print(e)
        else:
            for k, v in policy_dict.items():
                if 'status' not in v or v.get('status') != 'disable':
                    srcintf, dstintf = re.sub(r'\"', '', v.get('srcintf')), re.sub(r'\"', '', v.get('dstintf'))
                    srcaddr = ','.join(sip for sip in re.split(r'\s', re.sub(r'\"', '', v.get('srcaddr'))))
                    dstaddr = ','.join(dip for dip in re.split(r'\s', re.sub(r'\"', '', v.get('dstaddr'))))
                    service = re.compile('|'.join(map(re.escape, replacements))).sub(
                        lambda match: replacements[match.group()], ','.join(
                            svc for svc in re.split(r'\s', re.sub(r'\"', '', v.get('service')))))
                    comments = re.sub(r'\"', '', v.get('comments')) if 'comments' in v else ''
                    data_policy = (int(k), srcintf, dstintf, '', '', srcaddr, dstaddr, service, comments, current_time, None)
                    try:
                        db.execute(DBStatements.ADD_POLICY.format(self.fw_name), data_policy)
                    except mysql.connector.Error as e:
                        print(e)
        print(f'Data insert into table \"{self.fw_name}\" is finished.')

    def parse_firewall_address(self, content: str) -> dict:
        fwaddress_block_reg = r'(?P<addr>.*firewall\saddress(.*\n)*?end)'
        content_reg = r'(?P<address_name>\".*\")(?P<set>(.*\n)*?.*next)'
        data = defaultdict(dict)

        for line in re.finditer(content_reg, re.search(fwaddress_block_reg, content).group('addr')):
            address_obj_name = re.sub(r'\"', '', line.group('address_name').strip())
            for i in re.split(r',', re.sub(r'\n', ',', (re.sub(r'.*(set\s|next)', '', line.group('set').strip())).strip())):
                attr, val = re.split(r'\s', i)[0], re.split(r'\s', i)[1:]
                data[address_obj_name][attr] = val
        return data

    def parse_addrgrp(self, db: mysql.connector.cursor, content: str) -> None:
        addrgrp_reg = r'(?P<addrgrp>.*addrgrp(.*\n)*?.*end)'
        content_reg = r'(?P<grp_name>.\"\w+.*\")(?P<set>(.*\n)*?.*next)'
        data = defaultdict(dict)

        for line in re.finditer(content_reg, re.search(addrgrp_reg, content).group('addrgrp')):
            data[re.compile(r'\"').sub('', line.group('grp_name').strip())] = re.sub(r'set\smember\s', '', line.group(3).strip())

        print(data)
        for k,v in data.items():
            for i in (re.split(',', re.sub(r'\"\s\"', ',', v).replace('"', ''))):
                print(i)

    def resync_fw_policy(self, db, content: str) -> None:
        config_data = self.parse_firewall_policy(content)
        db_data = defaultdict(dict)
        in_count, not_in_count, rest_count = 0, 0, 0

        db.execute(DBStatements.GET_POLICY.format(self.fw_name))
        for policy in db.fetchall():
            for i in zip(('srcintf', 'dstintf', 'userid', 'adminid', 'srcaddr', 'dstaddr', 'service', 'comment', 'addtime', 'nat'), policy[1:]):
                db_data[str(policy[0])][i[0]] = i[1]
        for k,v in config_data.items():
            srcintf, dstintf = re.sub(r'\"', '', v.get('srcintf')), re.sub(r'\"', '', v.get('dstintf'))
            sip, dip = ','.join(sip for sip in re.split(r'\s', re.sub(r'\"', '', v.get('srcaddr')))), ','.join(dip for dip in re.split(r'\s', re.sub(r'\"', '', v.get('dstaddr'))))
            serv = ','.join(svc for svc in re.split(r'\s', re.sub(r'\"', '', v.get('service'))))
            if k not in db_data:
                insert_data = (k, srcintf, dstintf, '', '', sip, dip, serv, (v.get('comment') if 'comment' in v else ''), current_time, (v.get('ippool') if 'nat' in v else None))
                print(f'{DBStatements.ADD_POLICY.format(self.fw_name), insert_data}')
                db.execute(DBStatements.ADD_POLICY.format(self.fw_name), insert_data)
                not_in_count +=1
            else:
                if((db_data[k]['srcintf'] != srcintf) or (db_data[k]['dstintf'] != dstintf) or (db_data[k]['srcaddr'] != sip) or (db_data[k]['dstaddr'] != dip)):
                    update_data = (srcintf, dstintf, sip, dip, serv, k)
                    print(f'{DBStatements.UPDATE_POLICY.format(self.fw_name, *update_data)}')
                    db.execute(DBStatements.UPDATE_POLICY.format(self.fw_name, *update_data))
                    in_count +=1
                else:
                    del db_data[k]

        if len(db_data) != 0:
            for rest_id in db_data.keys():
                print(f'{DBStatements.DEL_POLICY.format(self.fw_name, rest_id)}')
                db.execute(DBStatements.DEL_POLICY.format(self.fw_name, rest_id))
                rest_count +=1
        print(f'Number of policies not in DB: {not_in_count}. They will be inserted into the DB.')
        print(f'Number of policies that differ from the current DB data : {not_in_count}. they will be updated in the DB.')
        print(f'The rest of the data in the DB but not in Fortit config: {rest_count}. it will be deleted from the DB.')

class FirewallFactory:
    """Factory class to create appropriate firewall instances"""
    
    @staticmethod
    def create_firewall(fw_type: str, fw_name: str, config_path: str, config: Dict[str, Any]) -> Firewall:
        """
        Create a firewall instance based on the type
        Args:
            fw_type: Type of firewall (e.g., 'fortinet', 'f5')
            fw_name: Name of the firewall
            config_path: Path to the config file
            config: Dictionary containing firewall-specific configuration
        Returns:
            Firewall instance
        Raises:
            ValueError: If firewall type is not supported
        """
        firewalls = {
            'fortinet': FortinetFirewall,
            # Add more firewall types here as needed
        }
        
        if fw_type.lower() not in firewalls:
            raise ValueError(f"Unsupported firewall type: {fw_type}")
            
        return firewalls[fw_type.lower()](fw_name, config_path, config)

def backup_database() -> None:
    """Create a database backup"""
    backup_dir = Path(os.getenv('BACKUP_DIR', 'backups'))
    backup_dir.mkdir(exist_ok=True)
    
    backup_file = backup_dir / f'mysqlbk-{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.sql'
    cmd = f"mysqldump -u {os.getenv('DBUSER')} -p'{os.getenv('PASSWORD')}' --all-databases > {backup_file}"
    
    try:
        os.system(cmd)
        logger.info(f"Database backup created: {backup_file}")
    except Exception as e:
        logger.error(f"Failed to create database backup: {e}")
        raise

def main():
    """Main function to process firewall configurations"""
    try:
        database = dbsetup.Database()
        fw_config = json.loads(os.getenv("FW", "{}"))
        
        if not fw_config:
            logger.warning("No firewall configurations found in environment")
            return

        for fw_id, fw_data in fw_config.items():
            try:
                logger.info(f"Processing firewall: {fw_id}")
                
                # Create config dictionary
                config = {
                    'vdom_name': fw_data.get('vdom'),
                    'default_zone_name': fw_data.get('default_zone'),
                }
                
                # Create firewall info tuple
                fwinfo = (
                    fw_id,
                    fw_data.get('vdom'),
                    fw_data.get('name'),
                    fw_data.get('ip'),
                    fw_data.get('account'),
                    bcrypt.hashpw(fw_data.get('password', '').encode(), bcrypt.gensalt()),
                    '0',
                    fw_data.get('chtdeip')
                )
                
                # Create backup before processing
                backup_database()
                
                # Process firewall configuration
                with database as db:
                    config_path = fw_data.get('config')
                    if not config_path or not os.path.exists(config_path):
                        logger.error(f"Config file not found: {config_path}")
                        continue
                        
                    with open(config_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    firewall = FirewallFactory.create_firewall('fortinet', fw_id, config_path, config)
                    logger.info(f'Starting parse "{fw_id}" config.')
                    
                    #firewall.insert_vlan(db, content)
                    #firewall.insert_firewall_policy(db, content, fwinfo)
                    firewall.resync_fw_policy(db, content)
                    
                logger.info(f'Parsing "{fw_id}" config is finished.')
                
            except Exception as e:
                logger.error(f"Error processing firewall {fw_id}: {e}")
                continue
                
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise

if __name__ == "__main__":
    main()
