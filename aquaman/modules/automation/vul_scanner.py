# coding=utf-8
import time
from aquaman.modules.auto_scanner.port_scanner import PortScanner
from aquaman.modules.poc_vul.poc_scan import PocsuiteScan
from aquaman.lib.mongo_db import connectiondb, db_name_conf
from bson import ObjectId

instance_db = db_name_conf()['instance_db']
portinfo_db = db_name_conf()['portinfo_db']


class VulScanner:
    def __init__(self, instance_id):
        self.instance_id = instance_id
        self.instance_info = connectiondb(instance_db).find_one({"_id": ObjectId(self.instance_id)})
        self.info_list = []
        self.vul_type = ''

    def _get_portinfo(self):
        print "PocScanner._get_portinfo"
        array = connectiondb(portinfo_db).find({"instance_id": self.instance_id})
        for item in array:
            item['_id'] = "%s" % item['_id']
            self.info_list.append(item)

    def _save_webvul_result(self, portinfo_id, data):
        connectiondb(portinfo_db).update_one({"_id": ObjectId(portinfo_id)}, {"$set": {
            "vul_type": "web",
            "target_id": data['target_id'],  # awvs的target_id
            "scan_id": data['scan_id'],  # awvs的sacn_id
            "create_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }})

    def _save_pocvul_result(self, portinfo_id, data):
        if data:
            # self.vul_type = 'exploit'
            self.vul_type = 'pocsuite'
        connectiondb(portinfo_db).update_one({"_id": ObjectId(portinfo_id)}, {"$set": {
            "vul_type": self.vul_type, "vulnerabilities": data
        }})

    def _start_poc(self):
        print "VulScanner._start_poc"
        for info in self.info_list:
            print "info => name:{}; port:{}; state:{}".format(info['name'], info['port'], info['state'])

            # info['name']=http/https/null,进行web指纹判断
            # 情况1: 这个就很奇怪了, 能扫到但是状态为closed???
            if 'closed' == info['state']:
                continue

            # 用poc脚本打、内置多线程
            pocuite = PocsuiteScan(ip=self.instance_info['host'], service=info['name'], port=info['port'], app=info['product'], version=info['version'])
            result = pocuite.run()
            self._save_pocvul_result(info['_id'], result)

            # 情况2: Web直接提交AWVS任务，获取target_id、scan_id、session_id即可。后续聚合通过这三个查询对应的web漏洞详情。
            # 提交任务即返回，无需使用多线程
            # Poc扫描无结果的情况下再执行
            # if 'http' in info['name'] and not result:
            #     print "[+] http"
            #     awvs = AwvsScan(info['name'], self.instance_info['target'], info['port'])
            #     result = awvs.run()
            #     self._save_webvul_result(info['_id'], result)
            #     continue

        connectiondb(instance_db).update_one({"_id": ObjectId(self.instance_id)}, {"$set": {
            "status": 'Completed',
            "update_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }})

    def run(self):
        # 0.更新端口列表
        PortScanner(self.instance_id).run()
        # 1.端口列表信息赋值
        self._get_portinfo()
        # 2.开启漏洞检测
        self._start_poc()
