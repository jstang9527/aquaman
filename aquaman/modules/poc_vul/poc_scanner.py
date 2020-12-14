#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : TideSec
# @Time    : 18-5-14
# @File    : poc_scanner.py
# @Desc    : =_=!!

import time
from threading import Thread
from application import settings
from multiprocessing import Pool
from aquaman.lib.mongo_db import db_name_conf, connectiondb, connectiondb2
from utils.public import parse_target
from apscheduler.schedulers.blocking import BlockingScheduler
from bson import ObjectId
from pocsuite.api.cannon import Cannon
from func_timeout.exceptions import FunctionTimedOut
from utils.logger import get_logger
import logging

logging.basicConfig()
log = get_logger()
config_db = db_name_conf()['config_db']
tasks_db = db_name_conf()['tasks_db']
vul_db = db_name_conf()['vul_db']


def verify_poc(scan_info):
    frequency = connectiondb(config_db).find_one({'config_name': settings.CONFIG_NAME})['poc_frequency']
    plugin_name = scan_info['plugin_name']
    plugin_filename = scan_info['plugin_filename']
    target = scan_info['target']
    info = {"pocname": plugin_name, "pocstring": open(plugin_filename, 'r').read(), "mode": 'verify'}
    invoker = Cannon(target, info)
    log.info("[PocScanner] {}({}) verify poc({})  all_times: {}".format(scan_info['task_name'], scan_info['target'], plugin_name, frequency))
    for i in range(50):
        try:
            result = invoker.run()
            if i > frequency:  # 超过指定次数
                log.info("[PocScanner] {}({}) verify poc({}) more than {} times, result: {}".format(scan_info['task_name'], scan_info['target'], plugin_name, frequency, result))
                return
            if not result or result[-3][0] != 1:
                time.sleep(1)
                continue
            log.info("[PocScanner] {}({}) verify poc({}) in {} times, result: {}".format(scan_info['task_name'], scan_info['target'], plugin_name, i + 1, result[-1]))
            connectiondb(vul_db).insert({
                "plugin_id": scan_info['plugin_id'],
                "plugin_filename": scan_info['plugin_filename'],
                "plugin_name": scan_info['plugin_name'],
                "plugin_type": scan_info['plugin_type'],
                "plugin_app": scan_info['plugin_app'],
                "plugin_version": scan_info['plugin_version'],
                "plugin_desc": scan_info['plugin_desc'],
                "target": scan_info['target'],  # 非端口必须是172.31.50.222:8080, 如果只有IP会使用脚本里的默认端口
                "task_id": scan_info['task_id'],
                "task_name": scan_info['task_name'],
                "scan_result": result[-1],
                "date": int(time.time()),
            })
            _save_result(scan_info['portinfo_id'], scan_info['plugin_app'])
            return
        except Exception as e:
            log.error("[PocScanner] {}({}) verify poc({}) in {} times, info: {}".format(scan_info['task_name'], scan_info['target'], plugin_name, i + 1, e))
            time.sleep(1)
            continue
        except FunctionTimedOut as e:
            log.error("[PocScanner] {}({}) verify poc({}) in {} times with timeout, info: {}".format(scan_info['task_name'], scan_info['target'], plugin_name, i + 1, e))
            time.sleep(1)
            continue


# 自动化探测任务需要更新端口应用版本状态
def _save_result(portinfo_id, app_name):
    portinfo_db = db_name_conf()['portinfo_db']
    # 看看是自定义任务还是自动化探测任务
    if not portinfo_id:
        return
    # 自动化任务需要更新端口应用版本
    connectiondb(portinfo_db).update_one({'_id': ObjectId(portinfo_id)}, {'$set': {
        'product': app_name
    }})


class PocsuiteScanner:
    def __init__(self, task_id):
        self.task_id = "{}".format(task_id)
        self.result = []
        self.plugin_db = db_name_conf()['plugin_db']
        self.connectiondb = connectiondb2('PocsuiteScanner')
        self.tasks_cursor = self.connectiondb[tasks_db].find_one({"_id": ObjectId(self.task_id)})
        self.target_list = parse_target(self.tasks_cursor['target_list'])
        self.pluginid_list = self.tasks_cursor['pluginid_list']
        self.processes = self.connectiondb[config_db].find_one({"config_name": settings.CONFIG_NAME})['poc_thread']
        self.tmp_app = ''  # 如果是自动化探测任务、一个端口只会对应一个应用。比如它匹配的是flink poc, 不管匹配哪个都会是plugin_app=apache flink

    def set_scanner(self):
        log.info("[PocScanner] {}({}) Task Start >>>.".format(self.tasks_cursor['task_name'], self.task_id))
        self.connectiondb[tasks_db].update_one({'_id': ObjectId(self.task_id)}, {'$set': {'status': 'Processing'}})
        self.connectiondb[vul_db].delete_many({"task_id": self.task_id})  # 清空旧任务的扫描结果
        pool_scanner = Pool(processes=self.processes)

        for target in self.target_list:
            for plugin_id in self.pluginid_list:
                plugin_info = self.connectiondb[self.plugin_db].find_one({"_id": ObjectId(plugin_id)})
                scan_info = {
                    "plugin_id": plugin_id,
                    "plugin_filename": plugin_info['plugin_filename'].encode("UTF-8"),
                    "plugin_name": plugin_info['plugin_name'].encode("UTF-8"),
                    "plugin_type": plugin_info['plugin_type'],
                    "plugin_app": plugin_info['plugin_app'],
                    "plugin_version": plugin_info['plugin_version'],
                    "plugin_desc": plugin_info['plugin_desc'].encode("UTF-8"),
                    "target": target,  # 非端口必须是172.31.50.222:8080, 如果只有IP会使用脚本里的默认端口
                    "task_id": self.task_id,
                    "task_name": self.tasks_cursor['task_name'],
                    "portinfo_id": self.tasks_cursor['portinfo_id']
                }
                self.tmp_app = plugin_info['plugin_app']
                pool_scanner.apply_async(verify_poc, (scan_info,))
        pool_scanner.close()
        pool_scanner.join()
        self.connectiondb[tasks_db].update_one({'_id': ObjectId(self.task_id)}, {'$set': {
            'status': 'Completed', 'update_at': int(time.time())
        }})
        log.info("[PocScanner] {}({}) Task Finished <<<.".format(self.tasks_cursor['task_name'], self.task_id))


class PocScannerLoop:
    def __init__(self):
        self.connectiondb = connectiondb2('PocScannerLoop')

    def task_schedule(self):
        scheduler = BlockingScheduler()
        try:
            scheduler.add_job(self._get_task, 'interval', seconds=60)
            scheduler.start()
        except Exception as e:
            log.error("[PocScannerLoop] Schedule Failed, Info: {}".format(e))

    def _get_task(self):
        log.info("[PocScannerLoop] Schedule Start.")
        for task_info in self.connectiondb[tasks_db].find():
            recursion = int(task_info['recursion'])
            task_id = '{}'.format(task_info['_id'])
            plan_time = int(time.time()) - task_info['update_at']

            # 超过5分钟还是processing状态的将重新执行
            if "Processing" in task_info['status']:
                if int(time.time()) < task_info['update_at'] + 60 * 3:
                    continue
                log.info("[PocScannerLoop] {}({}) process stats more than 3 min, try poc rescan...".format(task_info['task_name'], task_id))
                if not self.start_loop_scan(task_id):
                    log.error("[PocScannerLoop] {}({}) process stats more than 3 min, faield try poc rescan.".format(task_info['task_name'], task_id))
                    continue

            # once time
            if recursion == 0 and 'New' in task_info['status']:
                log.info("[PocScannerLoop] {}({}) One time Scan Start...".format(task_info['task_name'], task_id))
                if not self.start_loop_scan(task_id):
                    log.error("[PocScannerLoop] {}({}) One time Scan Failed.".format(task_info['task_name'], task_id))
                    continue

            # every day
            if recursion == 1:
                if plan_time > 60 * 60 * 24 * 1:
                    log.info("[PocScannerLoop] {}({}) Every Day Scan Start...".format(task_info['task_name'], task_id))
                    if not self.start_loop_scan(task_id):
                        log.error("[PocScannerLoop] {}({}) Every Day Scan Failed.".format(task_info['task_name'], task_id))
            # every week
            elif recursion == 7:
                if plan_time > 60 * 60 * 24 * 7:
                    log.info("[PocScannerLoop] {}({}) Every Week Scan Start...".format(task_info['task_name'], task_id))
                    if not self.start_loop_scan(task_id):
                        log.error("[PocScannerLoop] {}({}) Every Week Scan Failed.".format(task_info['task_name'], task_id))
            # every month task
            elif recursion == 30:
                if plan_time > 60 * 60 * 24 * 30:
                    log.info("[PocScannerLoop] {}({}) Every Month Week Scan Start...".format(task_info['task_name'], task_id))
                    if not self.start_loop_scan(task_id):
                        log.error("[PocScannerLoop] {}({}) Every Month Week Scan Failed.".format(task_info['task_name'], task_id))
        log.info("[PocScannerLoop] Schedule Finished.")

    def start_loop_scan(self, task_id):
        self.connectiondb[vul_db].delete_many({"task_id": task_id})
        self.connectiondb[tasks_db].update_one({"_id": ObjectId(task_id)}, {"$set": {
            "status": "Queued", "update_at": int(time.time())
        }})
        scanner = PocsuiteScanner(task_id)
        if scanner:
            t1 = Thread(target=scanner.set_scanner, args=())
            t1.start()
            return True
        return False


if __name__ == '__main__':
    loop_scanner = PocScannerLoop()
