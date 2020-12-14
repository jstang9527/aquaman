# coding=utf-8
import re
import nmap
import time
from aquaman.lib.mongo_db import db_name_conf, mongo_cli, connectiondb2
from bson import ObjectId
from aquaman.modules.automation.asset_scanner import AssetScanner
from threading import Thread
from apscheduler.schedulers.blocking import BlockingScheduler
from utils.logger import get_logger
log = get_logger()
discovery_db = db_name_conf()['discovery_db']
instance_db = db_name_conf()['instance_db']


class AssetDiscovery:
    def __init__(self, task_id):
        self.task_id = task_id
        self.cursor = mongo_cli[discovery_db].find_one({'_id': ObjectId(task_id)})
        self.target = self.cursor['target']

    def nmap_ping_scan(self, network_prefix):
        nm = nmap.PortScanner()     # 设置为nmap扫描状态。
        ping_scan_raw = nm.scan(hosts=network_prefix, arguments='-sn')   # hosts可以是单个IP地址也可以是一整个网段。    arguments就是运用什么方式扫描，-sn就是ping扫描。
        host_list_ip = []
        for result in ping_scan_raw['scan'].values():  # 将scan下面的数值赋值给result，并开始遍历。
            if result['status']['state'] == 'up':  # 如果是up则表明对方主机是存活的。
                host_list_ip.append(result['addresses']['ipv4'])   # 在addresses层下的ipv4，也就是IP地址添加到result字典中。
        return host_list_ip   # 返回字典。

    def match_target(self):
        # 单个目标 172.31.50.22 | default.com
        # 多个目标 172.31.50.22,default.com,
        # 网段 172.31.50.0/24
        # 连号网段 172.31.50.252-254
        # 连号和网段需要nmap批量扫描,确定的单个/多个目标直接发布资产扫描
        net_pattern = re.compile(r'\d+\.\d+\.\d+\.0/\d+')
        queue_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+-\d+')
        ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
        domain_pattern = re.compile(r'[a-zA-Z0-9\-]*\.?[a-zA-Z0-9\-]+\.[a-z]+')
        area_net = net_pattern.findall(self.target)
        if area_net:
            return {'array_ip': None, 'nmap_ip': area_net[0]}  # [172.31.50.0/24]
        queue_net = queue_pattern.findall(self.target)
        if queue_net:
            return {'array_ip': None, 'nmap_ip': queue_net[0]}  # ['172.31.50.222-225']
        ip_net = ip_pattern.findall(self.target)
        domain_net = domain_pattern.findall(self.target)
        if ip_net or domain_net:
            return {'array_ip': ip_net + domain_net, 'nmap_ip': None}  # ['172.31.50.222', 'www.mail.com']
        return False

    def publish_assettask(self, target):
        instance_data = {
            "hostname_type": "",                                                            # 主机类型
            "vendor": "",                                                                   # 设备
            "hostname": "",                                                                 # 主机名
            "host": "",                                                                     # IP
            "mac": "",                                                                      # mac地址
            "port_list": self.cursor['port_list'],                                          # 自定义端口(22,80,110),否则使用系统设置中的端口范围
            "name": time.strftime("%y%m%d", time.localtime()) + "_" + self.cursor['name'],  # 实例名
            "target": target,                                                               # 单个域名或IP
            "port_mode": self.cursor['user_port'],                                          # 0系统默认端口, 1自定义
            "recursion": self.cursor['recursion'],                                          # 扫描周期(0\1\7\30)
            "open_web": self.cursor['open_web'],                                            # 1开启web漏洞扫描
            "open_poc": self.cursor['open_poc'],                                            # 1开启poc扫描
            "open_auth": self.cursor['open_auth'],                                          # 1开启auth扫描
            "create_at": int(time.time()),
            "update_at": int(time.time()),
            "status": "Processing",
            "is_delete": 0,
            "discovery_id": self.task_id
        }
        _id = mongo_cli[instance_db].insert_one(instance_data).inserted_id
        scanner = AssetScanner('{}'.format(_id))
        t = Thread(target=scanner.run, args=())
        t.start()

    def run(self):
        result = self.match_target()
        target = []
        if not result:
            return False
        if result['nmap_ip']:  # 需要经过nmap扫描再进行发布
            target = self.nmap_ping_scan(result['nmap_ip'])
        else:
            target = result['array_ip']
        print "target>>>", target
        # 批量发布资产扫描服务
        for item in target:
            self.publish_assettask(item)
        # 存储
        mongo_cli[discovery_db].update_one({"_id": ObjectId(self.task_id)}, {"$set": {
            "discorvery": target,
            "status": 'Completed',
            "update_at": int(time.time()),
        }})


class AssetDiscoveryLoop:
    def __init__(self):
        # 资产扫描状态更新; 确认资产下属的所有任务完成后进行更新资产扫描状态
        self.connectiondb = connectiondb2('AssetDiscoveryLoop')

    def task_schedule(self):
        scheduler = BlockingScheduler()
        try:
            scheduler.add_job(self._get_task, 'interval', seconds=60)
            scheduler.start()
        except Exception as e:
            log.error("[AssetDiscoveryLoop] Schedule Failed, Info: {}".format(e))

    def _refresh_db(self, instance_id, instance_name):
        self.connectiondb[instance_db].update_one({"_id": ObjectId(instance_id)}, {"$set": {
            "status": "Completed",
            "update_at": int(time.time()),
        }})
        log.info("[AssetDiscoveryLoop] refresh {}({}) asset status(Completed).".format(instance_name, instance_id))

    def _get_task(self):
        log.info("[AssetDiscoveryLoop] Schedule Start.")
        for task_info in self.connectiondb[self.auth_db].find():
            recursion = int(task_info['recursion'])
            task_id = "{}".format(task_info['_id'])
            plan_time = int(time.time()) - task_info['date']

            if "Processing" in task_info['status']:  # todo 超过20分钟仍在扫描的就重新执行
                continue
            # once time
            if recursion == 0 and 'New' in task_info['status']:
                log.info("[AssetDiscoveryLoop] {}({}) One time Scan Start...".format(task_info['task_name'], task_id))
                if not self.start_loop_scan(task_id):
                    log.error("[AssetDiscoveryLoop] {}({}) One time Scan Failed...".format(task_info['task_name'], task_id))
                continue
            # every day
            if recursion == 1:
                if plan_time > 60 * 60 * 24 * 1:
                    log.info("[AssetDiscoveryLoop] {}({}) Every Day Scan Start...".format(task_info['task_name'], task_id))
                    if not self.start_loop_scan(task_id):
                        log.error("[AssetDiscoveryLoop] {}({}) Every Day Scan Failed...".format(task_info['task_name'], task_id))
            # every week
            elif recursion == 7:
                if plan_time > 60 * 60 * 24 * 7:
                    log.info("[AssetDiscoveryLoop] {}({}) Every Week Scan Start...".format(task_info['task_name'], task_id))
                    if not self.start_loop_scan(task_id):
                        log.error("[AssetDiscoveryLoop] {}({}) Every Week Scan Failed...".format(task_info['task_name'], task_id))
            # every month
            elif recursion == 30:
                if plan_time > 60 * 60 * 24 * 30:
                    log.info("[AssetDiscoveryLoop] {}({}) Every Month Week Scan Start...".format(task_info['task_name'], task_id))
                    if not self.start_loop_scan(task_id):
                        log.error("[AssetDiscoveryLoop] {}({}) Every Month Week Scan Failed...".format(task_info['task_name'], task_id))
        log.info("[AssetDiscoveryLoop] Schedule Finished.")
