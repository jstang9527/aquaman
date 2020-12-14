# coding=utf-8
import re
import json
import time
from flask import jsonify, request
from flask.views import MethodView
from utils.response import CommonResponseMixin, ReturnCode
from aquaman.modules.web_vul.awvs_api import AcunetixScanner
from aquaman.modules.automation.asset_scanner import AssetScanner
from aquaman.modules.discovery.asset_descovery import AssetDiscovery
from aquaman.lib.mongo_db import mongo_cli, db_name_conf
from application import settings
from bson import ObjectId
from threading import Thread

config_db = db_name_conf()['config_db']
instance_db = db_name_conf()['instance_db']
portinfo_db = db_name_conf()['portinfo_db']
auth_db = db_name_conf()['auth_db']  # auth
tasks_db = db_name_conf()['tasks_db']  # poc
vulscan_db = db_name_conf()['vulscan_db']  # web
weekpasswd_db = db_name_conf()['weekpasswd_db']  # auth detect
vul_db = db_name_conf()['vul_db']  # poc detect
plugin_db = db_name_conf()['plugin_db']


class InstanceInfoListView(MethodView, CommonResponseMixin):
    def get(self):
        """
        获取实例列表
        ---
        tags:
        - 实例管理
        definitions:
        - schema:
            id: dto.instance_list_output
            properties:
              data:
                type: object
                description: 实例列表
                properties:
                  list:
                    type: array
                    items:
                      type: dao.instance_info
                      $ref: '#/definitions/dao.instance_info'
                  total:
                    type: integer
              errmsg:
                type: string
                description: errno
              errno:
                type: integer
                description: errno
                default: 0
        parameters:
        - name: info
          in: query
          description: 实例名
          required: false
          type: string
        - name: page_size
          in: query
          description: 记录数
          required: true
          type: integer
        - name: page_no
          in: query
          description: 页码
          required: true
          type: integer
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.instance_list_output
              $ref: '#/definitions/dto.instance_list_output'
        """
        page_size = request.args.get('page_size', 10, int)
        page_no = request.args.get('page_no', 1, int)
        info = request.args.get('info', '', str)
        skip = page_size * (page_no - 1)
        total = mongo_cli[instance_db].find({"is_delete": {"$ne": 1}, "name": re.compile(info)}).count()
        dict_resp = mongo_cli[instance_db].find({"is_delete": {"$ne": 1}, "name": re.compile(info)}).limit(page_size).skip(skip).sort('update_at', -1)
        data = []
        for item in dict_resp:
            item['_id'] = "%s" % item['_id']
            item['create_at'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item['create_at']))
            item['update_at'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item['update_at']))
            data.append(item)

        response_data = self.wrap_json_response(data={'list': data, 'total': total}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)


# 实例信息
class InstanceInfoView(MethodView, CommonResponseMixin):
    # 获取实例详情信息, 关联表查询
    def get(self):
        """
        获取实例详情
        ---
        tags:
        - 实例管理
        definitions:
        - schema:
            id: dao.instance_info
            properties:
              _id:
                type: string
              hostname_type:
                type: string
                description: 主机类型
              vendor:
                type: string
                description: 设备
              hostname:
                type: string
                description: 域名
              host:
                type: string
                description: IP地址
              mac:
                type: string
              port_list:
                type: array
                description: 用户定义需要扫描的端口
                items:
                  type: integer
              portid_list:
                type: array
                description: 端口信息ID数组
                items:
                  type: string
              name:
                type: string
                description: 实例名
              target:
                type: string
                description: 目标(域名或IP)
              create_at:
                type: string
              update_at:
                type: string
              is_delete:
                type: integer
        - schema:
            id: dto.instance_info_output
            properties:
              data:
                type: dao.instance_info
                $ref: '#/definitions/dao.instance_info'
                description: response_data
              errmsg:
                type: string
                description: errno
              errno:
                type: integer
                description: errno
                default: 0
        parameters:
        - name: instance_id
          in: query
          description: 实例ID
          required: true
          type: string
        - name: simple
          in: query
          description: 单表信息
          required: false
          type: integer
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.instance_info_output
              $ref: '#/definitions/dto.instance_info_output'
        """
        _id = request.args.get('instance_id')

        instance_info = mongo_cli[instance_db].find_one({"_id": ObjectId(_id)})
        instance_info['_id'] = "%s" % instance_info['_id']
        # 仅仅单表信息
        simple = request.args.get('simple')
        if simple:
            return jsonify(self.wrap_json_response(data=instance_info, code=ReturnCode.SUCCESS))

        awvs_scan = AcunetixScanner()
        webvulns = awvs_scan.get_all()
        result = []
        # # 各端口的详细漏洞信息
        for portinfo in mongo_cli[portinfo_db].find({"is_delete": {"$ne": 1}, "instance_id": instance_info['_id']}):
            temp = []  # 单个端口的所有漏洞
            # [+]Web漏洞------------------------------------------------------------------------------
            portinfo_id = "%s" % portinfo['_id']
            # 获取web漏洞任务
            webtask_info = mongo_cli[vulscan_db].find_one({"portinfo_id": portinfo_id})
            if webtask_info:
                for vul in webvulns:
                    # print webtask_info['target_id'], "===", vul['target_id']
                    if webtask_info['target_id'][0] == vul['target_id']:
                        webtask_info['scan_id'] = vul['scan_id']
                        webtask_info['scan_session_id'] = vul['scan_session_id']
                        break
                # 三个ID获取web漏洞详情
                scan_id = webtask_info['scan_id']
                scan_session_id = webtask_info['scan_session_id']
                resp = awvs_scan.get_vullist(scan_id, scan_session_id)
                for vuln in resp['vulnerabilities']:
                    detail = awvs_scan.get_vuldetail(scan_id, scan_session_id, vuln['vuln_id'])
                    if detail:
                        temp.append({
                            'affects_url': re.sub('http://.*?/', '/', detail['affects_url']), 'vt_name': detail['vt_name'],
                            'description': re.sub('<.*?>', '', detail['description']), 'payload': detail['request'],
                            'exploit': detail['source'], 'impact': detail['impact'], 'tags': detail['tags'],
                            'attack_result': re.sub('<.*?>', '', detail['details']), 'method': 'Web Crawler',  # [todo] 识别方法
                            'severity': detail['severity']
                        })
            # [+]Auth漏洞---------------------------------------------------------------------------------
            # 先找auth task任务
            # 再找task对于的检出
            auth_task = mongo_cli[auth_db].find_one({"portinfo_id": portinfo_id})
            if auth_task:
                task_id = "%s" % auth_task['_id']
                wps = mongo_cli[weekpasswd_db].find({"task_id": task_id})
                for wp in wps:
                    temp.append({
                        'affects_url': wp['target'], 'vt_name': 'There are obvious loopholes in %s service certification' % wp['service'],
                        'description': 'There are obvious loopholes in %s service certification' % wp['service'], 'payload': wp['payload'],
                        'exploit': '', 'impact': '', 'tags': 'Week Password', 'severity': 3, 'method': 'Brute Force',  # [todo] 识别方法
                        'attack_result': {'service': wp['service'], 'username': wp['username'], 'password': wp['password']}
                    })
            # [+]Poc漏洞----------------------------------------------------------------------------------
            poc_task = mongo_cli[tasks_db].find_one({"portinfo_id": portinfo_id})
            if poc_task:
                task_id = "%s" % poc_task['_id']
                vulns = mongo_cli[vul_db].find({"task_id": task_id})
                for vuln in vulns:
                    try:
                        with open(vuln['plugin_filename']) as f:
                            poc_content = f.read()
                    except Exception as e:
                        poc_content = "file not found. info: %s" % e
                    temp.append({
                        'affects_url': vuln['target'], 'vt_name': vuln['plugin_name'],
                        'description': vuln['plugin_desc'], 'payload': poc_content,
                        'exploit': vuln['plugin_filename'], 'impact': '', 'tags': vuln['plugin_type'], 'severity': 3, 'method': 'Pocsuite',  # [todo] 识别方法
                        'attack_result': vuln['scan_result']
                    })
            # [*]Finished
            portinfo['vulnerabilities'] = temp
            portinfo['_id'] = "%s" % portinfo['_id']
            result.append(portinfo)
        instance_info['portinfo_list'] = result
        instance_info['create_at'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(instance_info['create_at']))
        instance_info['update_at'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(instance_info['update_at']))
        response_data = self.wrap_json_response(data=instance_info, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    # 创建实例, 只是存信息到数据库
    def post(self):
        """
        创建实例
        ---
        tags:
        - 实例管理
        definitions:
        - schema:
            id: dto.instance_create_input
            properties:
              port_list:
                type: array
                description: 需扫描端口列表
                items:
                  type: integer
              target:
                type: string
                description: 目标
              name:
                type: string
                description: 实例名
              recursion:
                type: integer
                description: 扫描周期
              open_web:
                type: integer
                description: 开启Web
              open_poc:
                type: integer
                description: 开启Poc
              open_auth:
                type: integer
                description: 开启Auth
              port_mode:
                type: integer
                description: 是否自定义端口
        parameters:
        - name: body
          in: body
          required: true
          schema:
            type: dto.instance_create_input
            $ref: '#/definitions/dto.instance_create_input'
        responses:
          '200':
            description: SUCCESS
            schema:
              id: dto.instance_create_output
              properties:
                data:
                  type: object
                  description: response_data
                  properties:
                    instance_id:
                      type: string
                      description: 实例ID
                errmsg:
                  type: string
                  description: errno
                errno:
                  type: integer
                  description: errno
                  default: 0
        """
        body_data = json.loads(request.get_data().decode())
        port_list = body_data['port_list']
        if not port_list:
            config_info = mongo_cli[config_db].find_one({"config_name": settings.CONFIG_NAME})
            port_list = config_info['port_list']

        instance_data = {
            "hostname_type": "",                   # 主机类型
            "vendor": "",                          # 设备
            "hostname": "",                        # 主机名
            "host": "",                            # IP
            "mac": "",                             # mac地址
            "port_list": port_list,                # 自定义端口(22,80,110-446),否则使用系统设置中的端口范围
            "name": body_data['name'],             # 实例名
            "target": body_data['target'],         # 单个域名或IP
            "port_mode": body_data['port_mode'],   # 0系统默认端口, 1自定义
            "recursion": body_data['recursion'],   # 扫描周期(0\1\7\30)
            "open_web": body_data['open_web'],     # 1开启web漏洞扫描
            "open_poc": body_data['open_poc'],     # 1开启poc扫描
            "open_auth": body_data['open_auth'],   # 1开启auth扫描
            "create_at": int(time.time()),
            "update_at": int(time.time()),
            "status": "New",
            "is_delete": 0,
        }

        instance_id = mongo_cli[instance_db].insert_one(instance_data).inserted_id
        if not instance_id:
            response_data = self.wrap_json_response(code=ReturnCode.FAILED)
            return jsonify(response_data)

        data = {'instance_id': '%s' % instance_id}
        response_data = self.wrap_json_response(data=data, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    # 更新实例信息
    def put(self):
        """
        更新实例信息
        ---
        tags:
        - 实例管理
        definitions:
        - schema:
            id: dto.instance_put_input
            properties:
              instance_id:
                type: string
                description: 实例ID
              port_list:
                type: array
                description: 需扫描端口列表
                items:
                  type: integer
              target:
                type: string
                description: 目标
              name:
                type: string
                description: 实例名
        parameters:
        - name: body
          in: body
          required: true
          schema:
            type: dto.instance_put_input
            $ref: '#/definitions/dto.instance_put_input'
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        body_data = json.loads(request.get_data().decode())
        _id = body_data['instance_id']
        if not _id:
            response_data = self.wrap_json_response(errmsg="Lost Params.", code=ReturnCode.WRONG_PARAMS)
            return jsonify(response_data)

        port_list = body_data['port_list']
        if not port_list:
            config_info = mongo_cli[config_db].find_one({"config_name": settings.CONFIG_NAME})
            port_list = config_info['port_list']

        mongo_cli[instance_db].update_one({"_id": ObjectId(_id)}, {"$set": {
            "name": body_data['name'],
            "target": body_data['target'],
            "update_at": int(time.time()),
            "port_list": port_list,
        }})
        response_data = self.wrap_json_response(data="success", code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    # 删除实例
    def delete(self):
        """
        删除实例及其端口信息
        ---
        tags:
        - 实例管理
        parameters:
        - name: id
          in: query
          description: 实例ID
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        # 删除实例
        # 删除端口信息
        _id = request.args.get('id')
        portinfo_db = db_name_conf()['portinfo_db']
        mongo_cli[portinfo_db].delete_many({"instance_id": _id})
        # connectiondb(instance_db).update({'_id': ObjectId(_id)}, {"$set": {"is_delete": 1}}, multi=True)
        mongo_cli[instance_db].delete_one({'_id': ObjectId(_id)})
        response_data = self.wrap_json_response(data='success', code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    # 开启实例扫描
    def patch(self):
        """
        开启实例扫描(立即扫描)
        ---
        tags:
        - 实例管理
        parameters:
        - name: id
          in: query
          description: 实例ID
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        # type=port  《资产探测》扫描端口,并更新端口信息数据: 实例与端口=一对多
        # type=poc   《漏洞探测》(涉及三个功能{Web探测,Poc,hydra})匹配并进行漏洞扫描、攻击; 端口与三个功能=一对多
        # 是否开启Web、Poc、hydra等, 始终开启nmap扫描
        _id = request.args.get('id')
        if not _id:
            response_data = self.wrap_json_response(code=ReturnCode.WRONG_PARAMS)
            return jsonify(response_data)

        resp = mongo_cli[instance_db].find_one({"_id": ObjectId(_id)})
        if not resp:
            return jsonify(self.wrap_json_response(code=ReturnCode.RESOURCE_NOT_EXISTS))

        # 0.频繁扫描
        if "New" != resp['status']:
            plan_time = int(time.time()) - resp['update_at']
            if plan_time < 60 * 1:  # 小于1分钟
                return jsonify(self.wrap_json_response(errmsg="task buzy...", code=ReturnCode.FAILED))

        mongo_cli[instance_db].update_one({"_id": ObjectId(_id)}, {"$set": {
            "status": "Processing",
            "update_at": int(time.time())
        }})

        # 立即重扫
        scanner = AssetScanner(_id)
        t1 = Thread(target=scanner.run, args=())
        t1.start()

        response_data = self.wrap_json_response(data="success", code=ReturnCode.SUCCESS)
        return jsonify(response_data)


# 批量探测任务列表
class AssetTaskList(MethodView, CommonResponseMixin):
    def get(self):
        discovery_db = db_name_conf()['discovery_db']
        cursor = mongo_cli[discovery_db].find()
        array = []
        for item in cursor:
            item['_id'] = '{}'.format(item['_id'])
            item['create_at'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item['create_at']))
            item['update_at'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item['update_at']))
            array.append(item)
        total = len(array)
        response_data = self.wrap_json_response(data={"list": array, "total": total}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)


# 批量探测任务
class AssetTask(MethodView, CommonResponseMixin):
    def get(self):
        task_id = request.args.get('id')
        if not task_id:
            return jsonify(self.wrap_json_response(code=ReturnCode.WRONG_PARAMS))

        discovery_db = db_name_conf()['discovery_db']
        cursor = mongo_cli[discovery_db].find_one({'_id': ObjectId(task_id)})
        if not cursor:
            return jsonify(self.wrap_json_response(code=ReturnCode.RESOURCE_NOT_EXISTS))

        cursor['_id'] = '{}'.format(cursor['_id'])
        return jsonify(self.wrap_json_response(data=cursor, code=ReturnCode.SUCCESS))

    def post(self):
        body_data = json.loads(request.get_data().decode())
        port_list = body_data['port_list']
        if not port_list:
            config_info = mongo_cli[config_db].find_one({"config_name": settings.CONFIG_NAME})
            port_list = config_info['port_list']

        discovery_db = db_name_conf()['discovery_db']
        task_info = {
            "name": body_data['name'],             # 任务名
            "port_list": port_list,                # 自定义端口(22,80,110-446),否则使用系统设置中的端口范围
            "target": body_data['target'],         # 网段
            "user_port": body_data['user_port'],   # 0系统默认端口, 1自定义
            "recursion": body_data['recursion'],   # 扫描周期(0\1\7\30)
            "open_web": body_data['open_web'],     # 1开启web漏洞扫描
            "open_poc": body_data['open_poc'],     # 1开启poc扫描
            "open_auth": body_data['open_auth'],   # 1开启auth扫描
            "user": body_data['user'],             # 操作员
            "create_at": int(time.time()),
            "update_at": int(time.time()),
            "discorvery": [],
            "status": "New",
            "is_delete": 0,
        }

        task_id = mongo_cli[discovery_db].insert_one(task_info).inserted_id
        if not task_id:
            response_data = self.wrap_json_response(code=ReturnCode.FAILED)
            return jsonify(response_data)

        data = {'task_id': '%s' % task_id}
        response_data = self.wrap_json_response(data=data, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    def put(self):
        body_data = json.loads(request.get_data().decode())
        port_list = body_data['port_list']
        task_id = body_data['task_id']
        if not task_id:
            return jsonify(self.wrap_json_response(data=ReturnCode.WRONG_PARAMS))
        if not port_list:
            config_info = mongo_cli[config_db].find_one({"config_name": settings.CONFIG_NAME})
            port_list = config_info['port_list']

        discovery_db = db_name_conf()['discovery_db']
        mongo_cli[discovery_db].update_one({"_id": ObjectId(task_id)}, {"$set": {
            # "name": body_data['name'],
            "port_list": port_list,
            "target": body_data['target'],
            "user_port": body_data['user_port'],
            "recursion": body_data['recursion'],
            "open_web": body_data['open_web'],
            "open_poc": body_data['open_poc'],
            "open_auth": body_data['open_auth'],
            "user": body_data['user'],
            "discorvery": [],
            # "update_at": int(time.time()),
        }})
        response_data = self.wrap_json_response(data="success", code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    def delete(self):
        task_id = request.args.get('id')
        if not task_id:
            return jsonify(self.wrap_json_response(code=ReturnCode.WRONG_PARAMS))

        discovery_db = db_name_conf()['discovery_db']
        dc = mongo_cli[discovery_db].delete_one({'_id': ObjectId(task_id)}).deleted_count
        if not dc:
            return jsonify(self.wrap_json_response(code=ReturnCode.RESOURCE_NOT_EXISTS))

        return jsonify(self.wrap_json_response(data={'task_id': task_id}, code=ReturnCode.SUCCESS))

    # 立即重扫
    def patch(self):
        task_id = request.args.get('id')
        if not task_id:
            return jsonify(self.wrap_json_response(code=ReturnCode.WRONG_PARAMS))

        discovery_db = db_name_conf()['discovery_db']
        if not mongo_cli[discovery_db].find({"_id": ObjectId(task_id)}).count():
            return jsonify(self.wrap_json_response(code=ReturnCode.RESOURCE_NOT_EXISTS))

        mongo_cli[discovery_db].update_one({"_id": ObjectId(task_id)}, {"$set": {
            "status": "Processing"
        }})
        ader = AssetDiscovery(task_id)
        t = Thread(target=ader.run, args=())
        t.start()
        return jsonify(self.wrap_json_response(data={'task_id': task_id}, code=ReturnCode.SUCCESS))


class ServiceList(MethodView, CommonResponseMixin):
    def get(self):
        page_size = request.args.get('limit', 10, int)
        page_no = request.args.get('page', 1, int)
        info = request.args.get('info', '', str)
        history = request.args.get('history', 0, int)  # 默认0不开启
        if history:
            query = {"instance_id": re.compile(info)}
        else:
            query = {"is_delete": {"$ne": 1}, "instance_id": re.compile(info)}
        skip = page_size * (page_no - 1)
        total = mongo_cli[portinfo_db].find(query).count()
        portinfo_cursor = mongo_cli[portinfo_db].find(query).limit(page_size).skip(skip).sort('update_at', -1)
        array = []
        for item in portinfo_cursor:
            item['_id'] = "{}".format(item['_id'])
            item['vul_high'] = 0
            item['vul_medium'] = 0
            item['vul_low'] = 0
            item['vul_info'] = 0
            # auth 检出
            auth_task = mongo_cli[auth_db].find_one({"portinfo_id": item['_id']})
            if auth_task:
                item['vul_high'] += mongo_cli[weekpasswd_db].find({"task_id": "{}".format(auth_task['_id'])}).count()
            # poc 检出
            poc_task = mongo_cli[tasks_db].find_one({"portinfo_id": item['_id']})
            if poc_task:
                item['vul_high'] += mongo_cli[vul_db].find({"task_id": "{}".format(poc_task['_id'])}).count()
            # web检出, 比较复杂
            awvs_scan = AcunetixScanner()
            webvulns = awvs_scan.get_all()
            web_task = mongo_cli[vulscan_db].find_one({"portinfo_id": item['_id']})
            if web_task:
                for vul in webvulns:
                    if web_task['target_id'][0] != vul['target_id']:
                        continue
                    item['vul_high'] += vul['vul_high']
                    item['vul_medium'] += vul['vul_medium']
                    item['vul_low'] += vul['vul_low']
                    item['vul_info'] += vul['vul_info']
                    break

            array.append(item)
        response_data = self.wrap_json_response(data={'list': array, 'total': total}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)
