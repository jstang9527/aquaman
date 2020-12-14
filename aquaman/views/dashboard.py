# coding=utf-8
import time
from flask import jsonify
from flask.views import MethodView
from utils.response import ReturnCode, CommonResponseMixin
from aquaman.lib.mongo_db import mongo_cli, db_name_conf

plugin_db = db_name_conf()['plugin_db']
auth_db = db_name_conf()['auth_db']
weekpasswd_db = db_name_conf()['weekpasswd_db']
vul_db = db_name_conf()['vul_db']
tasks_db = db_name_conf()['tasks_db']
vulscan_db = db_name_conf()['vulscan_db']  # web
instance_db = db_name_conf()['instance_db']


class TopCard(MethodView, CommonResponseMixin):
    def get(self):
        """
        图表聚合数据
        ---
        tags:
        - 首页大盘
        definitions:
        - schema:
            id: dao.dashboard_info
            properties:
              asset_count:
                type: integer
                description: 资产数量
              vul_count:
                type: integer
                description: 漏洞威胁
              tasks_old:
                type: array
                description: 昨日任务
                items:
                  type: integer
              tasks_now:
                type: array
                description: 今日任务
                items:
                  type: integer
              task_count:
                type: integer
                description: 总任务数
              plugin_count:
                type: integer
                description: 插件数
              legent:
                type: string
                description: 标签
              series:
                type: string
                description: [{'name': '', 'value': ''}]
        - schema:
            id: dto.dashboard_info_output
            properties:
              data:
                type: dao.dashboard_info
                $ref: '#/definitions/dao.dashboard_info'
                description: response_data
              errmsg:
                type: string
                description: errno
              errno:
                type: integer
                description: errno
                default: 0
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.dashboard_info_output
              $ref: '#/definitions/dto.dashboard_info_output'
        """
        # 插件数量
        plugin_count = mongo_cli[plugin_db].find().count()
        # 资产数
        asset_count = mongo_cli[instance_db].find().count()
        # 漏洞威胁=poc+auth
        poc_count = mongo_cli[vul_db].find().count()
        weekpassword_count = mongo_cli[weekpasswd_db].find().count()
        vul_count = poc_count + weekpassword_count

        # auth任务 date
        # 2.1 先过滤两天内的记录
        now = time.localtime()
        old = int(time.time()) - 60 * 60 * 24 * 2
        n_list = [0]
        for i in range(now.tm_hour):
            n_list.append(0)
        y_list = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        auth_data = mongo_cli[auth_db].find()
        for item in auth_data:
            # 如果两天之前直接过滤
            if item['date'] < old:
                continue
            timeArray = time.localtime(item['date'])
            # 今天的
            if timeArray.tm_mday == now.tm_mday:
                n_list[timeArray.tm_hour] += 1
                continue
            # 昨天的
            if timeArray.tm_mday == (now.tm_mday - 1):
                y_list[timeArray.tm_hour] += 1
                continue
        # 3. 漏洞类型
        vul_list = mongo_cli[vul_db].find()
        data = {}
        for vul in vul_list:
            if vul['plugin_type'] in data.keys():
                data[vul['plugin_type']] += 1
            else:
                data[vul['plugin_type']] = 1
        if 'Weak Password' in data.keys():
            data['Weak Password'] += weekpassword_count
        else:
            data['Weak Password'] = weekpassword_count
        series = []
        for k, v in data.items():
            series.append({'name': k, 'value': v})

        # 4. 综合结果
        result = {
            'vul_count': vul_count,
            'asset_count': asset_count,
            'plugin_count': plugin_count,
            'task_count': mongo_cli[auth_db].find().count() + mongo_cli[tasks_db].find().count() + mongo_cli[vulscan_db].find().count(),
            'tasks_now': n_list,
            'tasks_old': y_list,
            'legent': data.keys(),
            'series': series
        }
        # 今日任务数=实例的update+POC update+ AUTH update
        response_data = self.wrap_json_response(data=result, code=ReturnCode.SUCCESS)
        return jsonify(response_data)
