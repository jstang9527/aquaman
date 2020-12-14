# coding=utf-8
from apscheduler.schedulers.blocking import BlockingScheduler
from utils.logger import get_logger
from aquaman.lib.mongo_db import db_name_conf, connectiondb2
from aquaman.modules.web_vul.awvs_api import AcunetixScanner
from bson import ObjectId
import time
# import logging
# logging.basicConfig()
log = get_logger()


class AwvsTaskLoop:
    def __init__(self):
        # 更新Mongo中AWVS的任务状态
        # 定时从AWVS服务端的获取target_id的状态
        self.vulscan_db = db_name_conf()['vulscan_db']
        self.connectiondb = connectiondb2('AwvsTaskLoop')

    def task_schedule(self):
        scheduler = BlockingScheduler()  # 定时任务
        try:
            scheduler.add_job(self._get_task, 'interval', seconds=60)
            scheduler.start()
        except Exception as e:
            log.error("[AwvsTaskLoop] Schedule Failed, Info: {}".format(e))

    def _refresh_db(self, task_info):
        task_id = "{}".format(task_info['_id'])
        self.connectiondb[self.vulscan_db].update_one({"_id": ObjectId(task_id)}, {"$set": {
            "status": task_info['status'], "update_at": int(time.time()),
        }})
        log.info("[AwvsTaskLoop] refresh {}({}) asset status({}).".format(task_info['task_name'], task_id, task_info['status']))

    def _get_task(self):
        log.info("[AwvsTaskLoop] Schedule Start.")
        vuln_tasks = self.connectiondb[self.vulscan_db].find()
        if not vuln_tasks:
            log.info("[AwvsTaskLoop] Finished AwvsTaskLoop Task...(no any records).")
            return

        need_refresh_tasks = []  # 需要刷新的列表任务
        for item in vuln_tasks:
            if 'completed' in item['status'] or 'aborted' in item['status'] or 'failed' in item['status']:  # 已经完成的无需刷新
                continue
            need_refresh_tasks.append(item)

        if not need_refresh_tasks:
            log.info("[AwvsTaskLoop] Finished AwvsTaskLoop Task...(no need tasks).")
            return

        # 确认mongo需要更新的状态字段再去查awvs数据库，避免非必要查询
        awvs_tasks = AcunetixScanner().get_all()
        for item in need_refresh_tasks:
            flag = True
            ss = ''  # 一错就错
            for target in item['target_id']:
                if not flag:
                    break
                for record in awvs_tasks:
                    if target != record['target_id']:
                        continue
                    # 对上了
                    if 'process' in record['status']:
                        flag = False
                        break
                    if 'failed' in record['status'] or 'aborted' in record['status']:
                        ss = record['status']
                        break
            if flag:
                if ss:
                    item['status'] = ss
                else:
                    item['status'] = 'completed'
                self._refresh_db(item)

        log.info("[AwvsTaskLoop] Schedule Finished.")
