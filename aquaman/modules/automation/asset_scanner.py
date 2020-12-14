# coding=utf-8
import time
from random import sample
from bson import ObjectId
from aquaman.modules.automation.port_scanner import PortScanner
from aquaman.lib.mongo_db import db_name_conf, mongo_cli, connectiondb2
from apscheduler.schedulers.blocking import BlockingScheduler
from aquaman.modules.web_vul.awvs_api import AcunetixScanner
from utils.public import port_service
from string import digits, ascii_lowercase
from utils.logger import get_logger
from application import settings
# import logging


# logging.basicConfig()
log = get_logger()

tasks_db = db_name_conf()['tasks_db']
config_db = db_name_conf()['config_db']
instance_db = db_name_conf()['instance_db']
portinfo_db = db_name_conf()['portinfo_db']
auth_db = db_name_conf()['auth_db']
vulscan_db = db_name_conf()['vulscan_db']
plugin_db = db_name_conf()['plugin_db']


# Web 任务发布(内置异步)
def web_publish(target, port_info):
    if 'http' not in port_info['name']:  # 非Web跳过
        return
    print "AssetScanner.web_publish"
    # target必须是IP或者域名，而且不携带协议
    if port_info['port'] == '80':
        target = 'http://' + target
    elif port_info['port'] == '443':
        target = 'https://' + target
    else:  # 其他端口
        target = port_info['name'] + '://' + target + ':' + port_info['port']
    scan_dict = AcunetixScanner().start_task(target, " automation", "0")  # 0完全扫描

    mongo_cli[vulscan_db].insert_one({
        "task_name": time.strftime("%y%m%d", time.localtime()) + ''.join(sample(digits + ascii_lowercase, 4)) + '_' + target.split('.')[-1],
        "target_list": [target],
        "scan_type": "0",
        "description": target + " automation",
        "status": "processing",
        "target_id": [scan_dict['target_id']],
        "portinfo_id": "{}".format(port_info['_id']),
        "date": int(time.time()),
    })


# AUTH 任务发布, 只发布，然调度器去执行
def auth_publish(target, port_info):
    print "AssetScanner.auth_publish"
    # 先判断是否在指定配置服务
    auth_service = mongo_cli[config_db].find_one({"config_name": settings.CONFIG_NAME})['auth_service']
    if port_info['name'] not in auth_service:
        return
    auth_info = {
        "task_name": time.strftime("%y%m%d", time.localtime()) + ''.join(sample(digits + ascii_lowercase, 4)) + '_' + target.split('.')[-1],
        "target": [target],
        "portinfo_id": '{}'.format(port_info['_id']),
        "service": [port_info['name']],
        "recursion": 0,  # 仅一次扫描
        "status": "New",
        "args": "-s " + port_info['port'],  # 指定非默认端口, 这里注定只能写一个端口即服务
        "date": int(time.time()),
        "week_count": 0,
    }
    mongo_cli[auth_db].insert_one(auth_info)


def match_poc_plugin(port_info):
    plugin_array = mongo_cli[plugin_db].find()
    pid_list = []
    app = port_info['product']
    version = port_info['version']
    service = port_info['name']
    port = port_info['port']
    for plugin in plugin_array:
        # 1.有应用
        if app and app.lower() in plugin["plugin_app"].lower():
            # 1.1有版本，匹配该版本漏洞
            if version and version.lower() in plugin["plugin_version"].lower():
                pid_list.append("{}".format(plugin['_id']))
                print "has app and version app(%s) p_app(%s) ver(%s) p_ver(%s)" % (app, plugin["plugin_app"], version, plugin["plugin_version"])
                continue
            # 1.2具体版本没匹配到, 则匹配所有版本漏洞
            print "has app but not version(%s) (%s)" % (app, plugin["plugin_app"])
            pid_list.append("{}".format(plugin['_id']))
            continue

        # 2.应用的没匹配到，则进行服务匹配
        if service and service.lower() in plugin["default_service"]:
            print "has srv but not app(%s) (%s)" % (service, plugin["plugin_app"])
            pid_list.append("{}".format(plugin['_id']))
            continue

        # 3.服务不对称、没匹配到, 例如es =>wap-wsp
        srv = port_service(port)  # 匹配默认服务
        if not srv:
            continue
        if srv['service'] in plugin['default_service']:
            pid_list.append("{}".format(plugin['_id']))
    return pid_list


# POC 任务发布
def poc_publish(target, port_info):
    print "AssetScanner.poc_publish", port_info['port']
    # 1.配对Poc插件
    plugins = match_poc_plugin(port_info)
    # print "plugins》》》》》", plugins
    if not plugins:
        return

    # 2.存数据库并执行
    task_data = {
        "portinfo_id": "{}".format(port_info['_id']),
        "task_name": time.strftime("%y%m%d", time.localtime()) + ''.join(sample(digits + ascii_lowercase, 4)) + '_' + target.split('.')[-1],
        "status": "New",
        "target_list": [target + ':' + port_info['port']],
        "recursion": 0,
        "pluginid_list": plugins,
        "create_at": int(time.time()),
        "update_at": int(time.time())
    }
    mongo_cli[tasks_db].insert_one(task_data)


# instance没有与portinfo关联
class AssetScanner:
    def __init__(self, instance_id):
        self.instance_id = instance_id
        self.connectiondb = connectiondb2('AssetScanner')
        self.instance_cursor = self.connectiondb[instance_db].find_one({"_id": ObjectId(instance_id)})
        self.portinfo_cursor = self.connectiondb[portinfo_db].find({"is_delete": {"$ne": 1}, "instance_id": instance_id})
        self.name = self.instance_cursor['name']

    def set_tasks(self):
        for item in self.portinfo_cursor:  # 端口列表
            if 'closed' == item['state'] or 'unknown' in item['name'] or not item['name']:
                continue
            if self.instance_cursor['open_web']:
                web_publish(self.instance_cursor['target'], item)  # 一个端口只能对应一个web服务，所以target_id为长度1, target_list长度为1,
            if self.instance_cursor['open_auth']:
                auth_publish(self.instance_cursor['target'], item)
            if self.instance_cursor['open_poc']:
                poc_publish(self.instance_cursor['target'], item)

    # 先全扫
    def run(self):
        log.info("[AssetScanner] {}({}) Task Start >>>.".format(self.name, self.instance_id))
        PortScanner(self.instance_id).run()  # 0.更新端口列表(端口ID会变), 与之对应的旧任务先保存
        log.info("[AssetScanner] {}({}) set_tasks.".format(self.name, self.instance_id))
        self.set_tasks()
        log.info("[AssetScanner] {}({}) Task Finished <<<.".format(self.name, self.instance_id))


class AssetScannerLoop:
    def __init__(self):
        # 资产扫描状态更新; 确认资产下属的所有任务完成后进行更新资产扫描状态
        self.connectiondb = connectiondb2('AssetScannerLoop')

    def task_schedule(self):
        scheduler = BlockingScheduler()
        try:
            scheduler.add_job(self._get_task, 'interval', seconds=30)
            scheduler.start()
        except Exception as e:
            log.error("[AssetScannerLoop] Schedule Failed, Info: {}".format(e))

    def _refresh_db(self, instance_id, instance_name):
        self.connectiondb[instance_db].update_one({"_id": ObjectId(instance_id)}, {"$set": {
            "status": "Completed",
            "update_at": int(time.time()),
        }})
        log.info("[AssetScannerLoop] refresh {}({}) asset status(Completed).".format(instance_name, instance_id))

    def _get_task(self):
        log.info("[AssetScannerLoop] Schedule Start.")
        AssetInstanceList = self.connectiondb[instance_db].find()
        if not AssetInstanceList:
            log.info('[AssetScannerLoop] Schedule Finished.(no records)')

        for item in AssetInstanceList:
            if item['status'] == 'Completed':
                continue
            all_tasks_status = True
            if not all_tasks_status:  # 端口的所有任务成功才算成功
                continue
            # 先找到端口信息列表, 再逐个通过端口信息id查对应的各种任务状态 {"is_delete": {"$ne": 1}, "instance_id": re.compile(info)}
            instance_id = "{}".format(item['_id'])
            portinfo_cursors = self.connectiondb[portinfo_db].find({"is_delete": {"$ne": 1}, "instance_id": instance_id})
            if not portinfo_cursors.count():  # 一个端口信息都没有
                plan_time = int(time.time()) - item['update_at']
                log.info('[AssetScannerLoop] The {}({}) does not have any port.(no records)'.format(item['name'], instance_id))
                if plan_time > 300:  # 超过五分钟都没端口信息, 就判定已经完成端口扫描
                    log.info('[AssetScannerLoop] The {}({}) does not have any port more than 5 minute'.format(item['name'], instance_id))
                    self._refresh_db(instance_id, item['name'])
                continue
            log.info('[AssetScannerLoop] Chech all child task status of {}({})'.format(item['name'], instance_id))
            for portinfo in portinfo_cursors:
                portinfo_id = "{}".format(portinfo['_id'])
                # auth 任务
                auth_task = self.connectiondb[auth_db].find_one({"portinfo_id": portinfo_id})
                if auth_task and 'Completed' not in auth_task['status']:  # 有任务并且任务未完成
                    log.info('[AssetScannerLoop] {}({}) auth task is unok'.format(item['name'], instance_id))
                    all_tasks_status = False
                    break
                # poc 任务
                poc_task = self.connectiondb[tasks_db].find_one({"portinfo_id": portinfo_id})
                if poc_task and 'Completed' not in poc_task['status']:  # 有任务并且任务未完成
                    log.info('[AssetScannerLoop] {}({}) poc task is unok'.format(item['name'], instance_id))
                    all_tasks_status = False
                    break
                # web 任务
                vuln_task = self.connectiondb[vulscan_db].find_one({"portinfo_id": portinfo_id})
                if vuln_task and 'processing' in vuln_task['status']:  # 有任务且未完成
                    log.info('[AssetScannerLoop] {}({}) web task is unok'.format(item['name'], instance_id))
                    all_tasks_status = False
                    break
            if all_tasks_status:
                self._refresh_db(instance_id, item['name'])
        log.info("[AssetScannerLoop] Schedule Finished.")
