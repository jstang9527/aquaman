# -*- coding: utf-8 -*-
import time
from threading import Thread
from application import settings
from multiprocessing import Pool
from aquaman.lib.mongo_db import db_name_conf, connectiondb2
from aquaman.modules.auth_vul.hydra_plugin import HydraScanner, ServiceCheck
from utils.public import parse_target
from apscheduler.schedulers.blocking import BlockingScheduler
from bson import ObjectId
from func_timeout.exceptions import FunctionTimedOut
from func_timeout import func_set_timeout
from utils.logger import get_logger
# import logging


# logging.basicConfig()
log = get_logger()


def hydra_scanner(target_list, service, username_list, password_list, args):
    start = HydraScanner(target_list, service, username_list, password_list, args)
    result = start.run()
    return result


def service_check(target_list, service, args):
    start = ServiceCheck(target_list, service, args)
    result = start.run()
    return result


class AuthCrack:
    def __init__(self, task_id):
        self.task_id = task_id
        self.check_result = {}  # 检测结果
        self.online_target = []  # 在线目标
        self.result_pool = []
        self.result = []
        self.week_count = 0

        self.auth_db = db_name_conf()['auth_db']
        self.config_db = db_name_conf()['config_db']
        self.weekpasswd_db = db_name_conf()['weekpasswd_db']
        self.connectiondb = connectiondb2('AuthCrack')

        self.task_cursor = self.connectiondb[self.auth_db].find_one({"_id": ObjectId(self.task_id)})
        self.task_name = self.task_cursor['task_name']  # 191030_ssh_check
        self.target_list = parse_target(self.task_cursor['target'])  # [u'192.168.1.141', u'192.168.1.141']
        self.service_list = self.task_cursor['service']  # [u'ssh']
        self.args = self.task_cursor['args']  # u''

        self.config_cursor = self.connectiondb[self.config_db].find_one({"config_name": settings.CONFIG_NAME})
        self.processes = self.config_cursor['auth_tester_thread']  # 50
        self.username_list = self.config_cursor['username_dict']  # ["root"]
        self.password_list = self.config_cursor['password_dict']  # [u'123456', u'password', u'111111', u'666666', u'1qaz2wsx', u'1qaz2wsx3edc.com']

    def set_task(self):
        try:
            log.info("[AuthCrack] {}({}) Task Start >>>.".format(self.task_name, self.task_id))
            self.run()
            log.info("[AuthCrack] {}({}) Task Finished <<<.".format(self.task_name, self.task_id))
        except FunctionTimedOut:
            log.error("[AuthCrack]  {}({}) Task Timeout <<<.".format(self.task_name, self.task_id))
            self.connectiondb[self.auth_db].update_one({"_id": ObjectId(self.task_id)}, {"$set": {"status": "Failed"}})

    @func_set_timeout(300)
    def run(self):
        self.connectiondb[self.auth_db].update_one({"_id": ObjectId(self.task_id)}, {"$set": {"status": "Processing"}})
        pool_b = Pool(processes=self.processes)
        for service in self.service_list:
            log.info("[AuthCrack] target_list={}; service={}".format(self.target_list, service))
            self.result.append(
                pool_b.apply_async(hydra_scanner, (self.target_list, service, self.username_list, self.password_list, self.args))
            )
        pool_b.close()
        pool_b.join()
        for res_b in self.result:
            if res_b.get():
                for i in res_b.get():
                    target = i['target']
                    service = i['service']
                    username = i['username']
                    password = i['password']
                    payload = i['payload']
                    self.save_result(target, service, username, password, payload)
        self.connectiondb[self.auth_db].update_one({"_id": ObjectId(self.task_id)}, {"$set": {"status": "Completed", "week_count": self.week_count}})
        log.info("[AuthCrack] {}({}) Save Result Done...".format(self.task_name, self.task_id))

    def save_result(self, target, service, username, password, payload):
        data = {
            "target": target,
            "service": service,
            "username": username,
            "password": password,
            "payload": payload,
            "date": int(time.time()),  # 时间戳
            "task_id": self.task_id,
            "task_name": self.task_name,
        }
        self.week_count += 1
        if not self.connectiondb[self.weekpasswd_db].insert_one(data).inserted_id:
            log.error("[AuthCrack] Failed Save Item Of {}({}) By {}({}), weekpassword id: ".format(target, service, self.task_name, self.task_id))
        log.info("[AuthCrack] Success Save Item Of {}({}) By {}({}), weekpassword id: ".format(target, service, self.task_name, self.task_id))


class AuthTesterLoop:
    def __init__(self):
        self.auth_db = db_name_conf()['auth_db']
        self.weekpasswd_db = db_name_conf()['weekpasswd_db']
        self.connectiondb = connectiondb2('AuthTesterLoop')

    def task_schedule(self):
        scheduler = BlockingScheduler()
        try:
            scheduler.add_job(self._get_task, 'interval', seconds=60)
            scheduler.start()
        except Exception as e:
            log.error("[AuthTesterLoop] Schedule Failed, Info: {}".format(e))

    def _get_task(self):
        log.info("[AuthTesterLoop] Schedule Start.")
        for task_info in self.connectiondb[self.auth_db].find():
            recursion = int(task_info['recursion'])
            task_id = "{}".format(task_info['_id'])
            plan_time = int(time.time()) - task_info['date']

            if "Processing" in task_info['status']:  # todo 超过20分钟仍在扫描的就重新执行
                continue
            # once time
            if recursion == 0 and 'New' in task_info['status']:
                log.info("[AuthTesterLoop] {}({}) One time Scan Start...".format(task_info['task_name'], task_id))
                if not self.start_loop_scan(task_id):
                    log.error("[AuthTesterLoop] {}({}) One time Scan Failed...".format(task_info['task_name'], task_id))
                continue
            # every day
            if recursion == 1:
                if plan_time > 60 * 60 * 24 * 1:
                    log.info("[AuthTesterLoop] {}({}) Every Day Scan Start...".format(task_info['task_name'], task_id))
                    if not self.start_loop_scan(task_id):
                        log.error("[AuthTesterLoop] {}({}) Every Day Scan Failed...".format(task_info['task_name'], task_id))
            # every week
            elif recursion == 7:
                if plan_time > 60 * 60 * 24 * 7:
                    log.info("[AuthTesterLoop] {}({}) Every Week Scan Start...".format(task_info['task_name'], task_id))
                    if not self.start_loop_scan(task_id):
                        log.error("[AuthTesterLoop] {}({}) Every Week Scan Failed...".format(task_info['task_name'], task_id))
            # every month
            elif recursion == 30:
                if plan_time > 60 * 60 * 24 * 30:
                    log.info("[AuthTesterLoop] {}({}) Every Month Week Scan Start...".format(task_info['task_name'], task_id))
                    if not self.start_loop_scan(task_id):
                        log.error("[AuthTesterLoop] {}({}) Every Month Week Scan Failed...".format(task_info['task_name'], task_id))
        log.info("[AuthTesterLoop] Schedule Finished.")

    def start_loop_scan(self, task_id):
        self.connectiondb[self.weekpasswd_db].delete_many({"task_id": task_id})
        self.connectiondb[self.auth_db].update_one({"_id": ObjectId(task_id)}, {"$set": {
            "status": "Queued", "date": int(time.time()), "week_count": 0,
        }})
        scanner = AuthCrack(task_id)
        if scanner:
            t1 = Thread(target=scanner.set_task, args=())
            t1.start()
            return True
        return False
