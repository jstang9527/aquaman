# coding=utf-8
import time
from aquaman.lib.mongo_db import db_name_conf, connectiondb2
from bson import ObjectId
from utils.nmapy import NmapScanner
from utils.public import port_service, http_server
from utils.spider import WebParser
from utils.ip_discern import getipinfo


class PortSocket:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def discern(self):
        return False


class PortScanner:
    def __init__(self, instance_id):
        self._id = instance_id
        self.args_val = '-sV'
        self.instance_db = db_name_conf()['instance_db']
        self.portinfo_db = db_name_conf()['portinfo_db']
        self.connectiondb = connectiondb2('PortScanner')
        self.instance_info = self.connectiondb[self.instance_db].find_one({"_id": ObjectId(self._id)})
        self.target_val = self.instance_info['target']
        self.ports_val = self._set_attr()

    def _set_attr(self):
        print "PortScanner._get_instance"
        ports_val = self.instance_info['port_list']
        return ','.join(str(i) for i in ports_val)

    """
    [*] 细粒度级端口服务识别
    [*] info['name']=http/https/null,进行web指纹判断
    [todo] 通过socket识别
    [-] info{'name':'', 'port':'', 'product':'', 'version':'', 'web_fingerprint':''}
    """
    def service_discern(self, ip, info):
        if not ip:
            return False
        # nmap没有识别到服务、应用
        if not info['name']:
            # 1.先进行网络爬虫判断是否是web应用
            wp = WebParser(ip, port=info['port'], scheme='http')
            data = wp.fingerprints()
            scheme = 'http'
            if not data:
                scheme = 'https'
                wp = WebParser(ip, port=info['port'], scheme='https')
                data = wp.fingerprints()
            # 1.1 确认web服务，并返回web指纹(但是有例外，比如mongo有web特性)
            if data:
                info['web_fingerprint'] = data
                srv = http_server(data['server'])
                if srv:
                    info['name'] = scheme
                    info['product'] = srv['product']
                    info['version'] = srv['version']
                return info

            # 2.非web服务, 使用socker进行识别
            ps = PortSocket(ip, port=info['port'])
            data = ps.discern()
            # 2.1 确认服务, 通过socket识别对于版本{'name': 'tcp', 'product':'cisco', 'version':'12.3.11'}
            if data:
                info['name'] = data['name']
                info['product'] = srv['product']
                info['version'] = srv['version']
                return info

            # 3.无法识别, 硬匹配默认端口服务, 有可能匹配不到
            srv_dict = port_service(info['port'])
            if srv_dict:
                info['name'] = srv_dict['service']
                return info
            else:
                return False

        # nmap识别出是web服务, 进行应用、版本确认
        elif 'http' in info['name']:
            # 1.先进行网络爬虫判断是否是web应用
            wp = WebParser(ip, port=info['port'], scheme=info['name'])
            data = wp.fingerprints()
            if data:
                info['web_fingerprint'] = data
                srv = http_server(data['server'])
                if srv:
                    info['product'] = srv['product']
                    info['version'] = srv['version']
                return info

        # nmap识别出服务,但未识别出为web服务,使用爬虫、socket二次确认确认(可能是http但是会标记其他服务,例如apache flink)
        else:
            # 1.爬虫确认
            scheme = 'http'
            wp = WebParser(ip, port=info['port'], scheme=scheme)
            data = wp.fingerprints()
            if not data:
                scheme = 'https'
                wp = WebParser(ip, port=info['port'], scheme=scheme)
                data = wp.fingerprints()
            if data:
                info['web_fingerprint'] = data
                srv = http_server(data['server'])
                if srv:
                    info['product'] = srv['product']
                    info['version'] = srv['version']
                return info
            # 2.确认服务, 通过socket识别对于版本{'name': 'tcp', 'product':'cisco', 'version':'12.3.11'}
            ps = PortSocket(ip=self.instance_info['host'], port=info['port'])
            data = ps.discern()
            # 2.1 确认服务, 通过socket识别对于版本{'name': 'tcp', 'product':'cisco', 'version':'12.3.11'}
            if data:
                info['name'] = data['name']
                info['product'] = srv['product']
                info['version'] = srv['version']
                return info
        # 无法识别, 维持原端口信息
        return False

    def _start_nmap(self):
        print "PortScanner._start_nmap"
        new_scan = NmapScanner(self.target_val, self.ports_val, self.args_val)
        result = new_scan.run()
        self._save_result(result)

    def _save_result(self, result):
        print "PortScanner._save_result"
        ip_info = getipinfo(result['host'])
        if not ip_info:
            ip_info = {'gps': '', 'isp': '', 'area': ''}
        # 1.更新实例信息
        self.connectiondb[self.instance_db].update_one({"_id": ObjectId(self._id)}, {"$set": {
            "hostname_type": result['hostname_type'],
            "vendor": result['vendor'],
            "hostname": result['hostname'],
            "host": result['host'],
            "mac": result['mac'],
            "ip_info": ip_info,
            "update_at": int(time.time()),
        }})
        # 2.插入隶属实例的新端口信息
        for port_info in result['ports']:
            if port_info['state'] == 'closed':
                continue
            port_info['web_fingerprint'] = ''
            info = {
                'name': port_info['name'],
                'port': port_info['port'],
                'product': port_info['product'],
                'version': port_info['version'],
                'web_fingerprint': port_info['web_fingerprint']
            }
            data = self.service_discern(ip=result['host'], info=info)
            if data:
                port_info['name'] = data['name']
                port_info['product'] = data['product']
                port_info['version'] = data['version']
                port_info['web_fingerprint'] = data['web_fingerprint']

            self.connectiondb[self.portinfo_db].insert_one({
                "instance_id": self._id,
                "product": port_info['product'],
                "state": port_info['state'],
                "version": port_info['version'],
                "protocol": port_info['protocol'],
                "name": port_info['name'],
                "conf": port_info['conf'],
                "reason": port_info['reason'],
                "extrainfo": port_info['extrainfo'],
                "port": port_info['port'],
                "cpe": port_info['cpe'],
                "web_fingerprint": port_info['web_fingerprint'],
                "is_delete": 0,
                "discovery_id": '',
            })

    def run(self):
        print "PortScanner.run"
        # 0.旧端口信息设置成历史值
        self.connectiondb[self.portinfo_db].update_many({"instance_id": self._id}, {"$set": {"is_delete": 1}})
        # 1.开始nmap扫描
        self._start_nmap()
