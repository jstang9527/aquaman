# -*- coding: utf-8 -*-
import json
import time
import re
from bson import ObjectId
from flask import jsonify, request
from threading import Thread
from application import settings
from aquaman.lib.mongo_db import mongo_cli, db_name_conf
from flask.views import MethodView
from utils.response import CommonResponseMixin, ReturnCode
from aquaman.modules.auth_vul.auth_scanner import AuthCrack

auth_db = db_name_conf()['auth_db']
weekpasswd_db = db_name_conf()['weekpasswd_db']


class AuthTesterConfigView(MethodView, CommonResponseMixin):
    # 提供创建所需数据 API
    def get(self):
        """
        提供创建所需数据 API
        ---
        tags:
        - 弱口令检测(auth_tester)
        definitions:
        - schema:
            id: dto.auth_tester_pagedata_output
            properties:
              data:
                type: object
                properties:
                  username_list:
                    type: array
                    description: 用户字典
                    items:
                      type: string
                  password_list:
                    type: array
                    description: 密码字典
                    items:
                      type: string
                  service:
                    type: array
                    description: 协议列表
                    items:
                      type: string
              errmsg:
                type: string
              errno:
                type: integer
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.auth_tester_pagedata_output
              $ref: '#/definitions/dto.auth_tester_pagedata_output'
        """
        config_db = db_name_conf()['config_db']
        config_info = mongo_cli[config_db].find_one({"config_name": settings.CONFIG_NAME})
        data = {
            "username_list": config_info['username_dict'],
            "password_list": config_info['password_dict'],
            "service": config_info['auth_service']
        }
        response_data = self.wrap_json_response(data=data, code=ReturnCode.SUCCESS)
        return jsonify(response_data)


class AuthTesterTasksView(MethodView, CommonResponseMixin):
    # 获取所有任务,分页模糊
    def get(self):
        """
        任务列表
        ---
        tags:
        - 弱口令检测(auth_tester)
        definitions:
        - schema:
            id: dto.auth_tester_tasklist_output
            properties:
              data:
                type: object
                description: 任务列表
                properties:
                  list:
                    type: array
                    description: 任务记录
                    items:
                      type: dao.auth_tester_taskinfo
                      $ref: '#/definitions/dao.auth_tester_taskinfo'
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
          description: 模糊查询
          required: false
          type: string
        - name: limit
          in: query
          description: 记录数
          required: true
          type: integer
        - name: page
          in: query
          description: 页码
          required: true
          type: integer
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.auth_tester_tasklist_output
              $ref: '#/definitions/dto.auth_tester_tasklist_output'
        """
        limit = request.args.get('limit', 10, int)
        page = request.args.get('page', 1, int)
        info = request.args.get('info', '', str)
        skip = limit * (page - 1)
        auth_db = db_name_conf()['auth_db']

        total = mongo_cli[auth_db].find({"task_name": re.compile(info)}).count()
        cursor = mongo_cli[auth_db].find({"task_name": re.compile(info)}).limit(limit).skip(skip).sort('date', -1)
        data = []
        for item in cursor:
            item['_id'] = "%s" % item['_id']
            item['date'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item['date']))
            data.append(item)

        response_data = self.wrap_json_response(data={"list": data, "total": total}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)


class AuthTesterTaskView(MethodView, CommonResponseMixin):
    # 获取任务详情,
    # 单个: /auth_tester/task?task_id=1
    def get(self):
        """
        获取任务详情
        ---
        tags:
        - 弱口令检测(auth_tester)
        definitions:
        - schema:
            id: dao.auth_tester_taskinfo
            properties:
              username:
                type: array
                description: 用户字典
                items:
                  type: string
              password:
                type: array
                description: 密码字典
                items:
                  type: string
              service:
                type: array
                description: 服务列表
                items:
                  type: string
              target:
                type: array
                description: 目标列表
                items:
                  type: string
              _id:
                type: string
                description: 任务ID
              task_name:
                type: string
                description: 任务名
              args:
                type: string
                description: 命令参数
              date:
                type: string
                description: 最后成功执行时间
              recursion:
                type: integer
                description: 执行周期(0:一次,1:每天,7:每周,30:每月)
              status:
                type: string
                description: 执行状态
              week_count:
                type: integer
                description: 威胁数量(失陷主机服务数)
        - schema:
            id: dto.auth_tester_taskinfo_output
            properties:
              data:
                type: dao.auth_tester_taskinfo
                $ref: '#/definitions/dao.auth_tester_taskinfo'
                description: response_data
              errmsg:
                type: string
                description: errno
              errno:
                type: integer
                description: errno
                default: 0
        parameters:
        - name: task_id
          in: query
          description: task_id
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.auth_tester_taskinfo_output
              $ref: '#/definitions/dto.auth_tester_taskinfo_output'
        """
        task_id = request.args.get('task_id')
        if task_id:
            auth_db = db_name_conf()['auth_db']
            dict_result = mongo_cli[auth_db].find_one({"_id": ObjectId(task_id)})
            dict_result['_id'] = "%s" % dict_result['_id']
            response_data = self.wrap_json_response(data=dict_result, code=ReturnCode.SUCCESS)
        else:
            response_data = self.wrap_json_response(errmsg="Lost params of task_id", code=ReturnCode.WRONG_PARAMS)
        return jsonify(response_data)

    # 创建任务
    def post(self):
        """
        创建任务
        ---
        tags:
        - 弱口令检测(auth_tester)
        definitions:
        - schema:
            id: dto.auth_tester_pagedata_input
            properties:
              service:
                type: array
                description: 协议列表
                items:
                  type: string
              target_list:
                type: array
                description: 目标列表
                items:
                  type: string
              task_name:
                type: string
                description: 任务名
              recursion:
                type: integer
                description: 任务执行周期(0/1/7/30),0为立即执行且仅执行一次
              args:
                type: string
                description: 默认留空即可，也可添加参数如-t 20进行设置线程数、-s 2121设置非标准端口等
        parameters:
        - name: body
          in: body
          required: true
          schema:
            type: dto.auth_tester_pagedata_input
            $ref: '#/definitions/dto.auth_tester_pagedata_input'
        responses:
          '200':
            description: SUCCESS
            schema:
              id: dto.auth_tester_newtask_output
              properties:
                data:
                  type: object
                  description: response_data
                  properties:
                    task_id:
                      type: string
                      description: 任务ID
                errmsg:
                  type: string
                  description: errno
                errno:
                  type: integer
                  description: errno
                  default: 0
        """
        body_data = json.loads(request.get_data().decode())
        auth_info = {
            "task_name": time.strftime("%y%m%d", time.localtime()) + "_" + body_data['task_name'],
            "target": body_data['target_list'],
            "instance_id": 'Null',
            "service": body_data['service'],
            "recursion": int(body_data['recursion']),
            "status": "Queued",
            "args": body_data['args'],
            "date": int(time.time()),
            "week_count": 0,
        }
        auth_db = db_name_conf()['auth_db']
        task_id = mongo_cli[auth_db].insert_one(auth_info).inserted_id
        data = {'task_id': "%s" % task_id}
        if task_id:
            scanner = AuthCrack(task_id)
            t1 = Thread(target=scanner.set_task, args=())
            t1.start()
            response_data = self.wrap_json_response(data=data, code=ReturnCode.SUCCESS)
            return jsonify(response_data)
        response_data = self.wrap_json_response(data=data, code=ReturnCode.INTERVAL_SERVER_ERROR)
        return jsonify(response_data)

    # 更新任务
    def put(self):
        """
        更新任务
        ---
        tags:
        - 弱口令检测(auth_tester)
        definitions:
        - schema:
            id: dto.auth_tester_put_input
            properties:
              task_id:
                type: string
                description: 任务ID
              service:
                type: array
                description: 协议列表
                items:
                  type: string
              target_list:
                type: array
                description: 目标列表
                items:
                  type: string
              task_name:
                type: string
                description: 任务名
              recursion:
                type: integer
                description: 任务执行周期(0/1/7/30),0为立即执行且仅执行一次
              args:
                type: string
                description: 默认留空即可，也可添加参数如-t 20进行设置线程数、-s 2121设置非标准端口等
        parameters:
        - name: body
          in: body
          required: true
          schema:
            type: dto.auth_tester_put_input
            $ref: '#/definitions/dto.auth_tester_put_input'
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        body_data = json.loads(request.get_data().decode())
        task_id = body_data['task_id']
        if not task_id:
            response_data = self.wrap_json_response(errmsg="require task_id params", code=ReturnCode.WRONG_PARAMS)
            return jsonify(response_data)

        auth_info = {
            "task_name": body_data['task_name'],
            "target": body_data['target_list'],
            "instance_id": 'Null',
            "service": body_data['service'],
            "recursion": int(body_data['recursion']),
            "args": body_data['args'],
        }
        dc = mongo_cli[auth_db].update_one({"_id": ObjectId(task_id)}, {"$set": auth_info}).modified_count
        if dc:
            response_data = self.wrap_json_response(code=ReturnCode.SUCCESS)
        else:
            response_data = self.wrap_json_response(errmsg='Failed Update Auth TaskInfo.', code=ReturnCode.FAILED)

        return jsonify(response_data)

    # 删除任务
    def delete(self):
        """
        删除任务
        ---
        tags:
        - 弱口令检测(auth_tester)
        definitions:
        - schema:
            id: dto.public_string_data_output
            properties:
              data:
                type: string
                description: response_data
              errmsg:
                type: string
                description: errmsg
              errno:
                type: integer
                description: errno
                default: 0
        parameters:
        - name: task_id
          in: query
          description: task_id
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        task_id = request.args.get('task_id')
        if not task_id:
            response_data = self.wrap_json_response(errmsg="Lost params of task_id", code=ReturnCode.WRONG_PARAMS)
            return jsonify(response_data)

        auth_db = db_name_conf()['auth_db']
        weekpasswd_db = db_name_conf()['weekpasswd_db']
        dc = mongo_cli[auth_db].delete_one({"_id": ObjectId(task_id)}).deleted_count
        if dc:
            mongo_cli[weekpasswd_db].delete_many({"task_id": task_id}).deleted_count
            response_data = self.wrap_json_response(data="success", code=ReturnCode.SUCCESS)
        else:
            response_data = self.wrap_json_response(errmsg="Failed Delete Record", code=ReturnCode.RESOURCE_NOT_EXISTS)
        return jsonify(response_data)

    # 重新扫描, 删除旧信息
    def patch(self):
        """
        重新扫描
        ---
        tags:
        - 弱口令检测(auth_tester)
        parameters:
        - name: task_id
          in: query
          description: task_id
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        task_id = request.args.get('task_id')
        if not task_id:
            response_data = self.wrap_json_response(errmsg="require task_id params", code=ReturnCode.WRONG_PARAMS)
            return jsonify(response_data)

        # 有无记录
        task_info = mongo_cli[auth_db].find_one({"_id": ObjectId(task_id)})
        if not task_info:
            return jsonify(self.wrap_json_response(code=ReturnCode.RESOURCE_NOT_EXISTS))

        # 0.频繁扫描
        plan_time = int(time.time()) - task_info['date']
        if plan_time < 60 * 3:  # 小于三分钟
            return jsonify(self.wrap_json_response(errmsg="task buzy...", code=ReturnCode.FAILED))
        # 1.删除旧信息
        mongo_cli[weekpasswd_db].delete_many({'task_id': task_id})
        # 2.更新任务状态
        dc = mongo_cli[auth_db].update_one({"_id": ObjectId(task_id)}, {"$set": {
            "status": "Queued",
            "date": int(time.time()),
            "week_count": 0,  # 弱口令数量, ssh ftp vnc....
        }}).modified_count
        # 3.执行扫描
        if dc:
            scanner = AuthCrack(task_id)
            t1 = Thread(target=scanner.set_task, args=())
            t1.start()
            response_data = self.wrap_json_response(data="success", code=ReturnCode.SUCCESS)
        else:
            response_data = self.wrap_json_response(errmsg="Failed Update TaskInfo.", code=ReturnCode.FAILED)
        return jsonify(response_data)


class AuthTesterDetectView(MethodView, CommonResponseMixin):
    def get(self):
        """
        检出目标列表
        ---
        tags:
        - 弱口令检测(auth_tester)
        definitions:
        - schema:
            id: dao.auth_tester_weekpasswd_info
            properties:
              _id:
                  type: string
                  description: _id
              date:
                type: string
                description: 扫描日期
              username:
                type: string
                description: 账户
              password:
                type: string
                description: 密码
              service:
                type: string
                description: 服务协议
              tag:
                type: string
                description: 标记(用来标记虚拟删除)
              target:
                type: string
                description: 目标
              task_id:
                type: string
                description: 隶属任务编号
              task_name:
                type: string
                description: 隶属任务
        - schema:
            id: dto.auth_tester_detectlist_output
            properties:
              data:
                type: object
                description: 检出列表
                properties:
                  total:
                    type: integer
                    description: 记录数
                  list:
                    type: array
                    description: 检出记录
                    items:
                      type: dao.auth_tester_weekpasswd_info
                      $ref: '#/definitions/dao.auth_tester_weekpasswd_info'
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
          description: 模糊查询
          required: false
          type: string
        - name: limit
          in: query
          description: 记录数
          required: true
          type: integer
        - name: page
          in: query
          description: 页码
          required: true
          type: integer
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.auth_tester_detectlist_output
              $ref: '#/definitions/dto.auth_tester_detectlist_output'
        """
        limit = request.args.get('limit', 10, int)
        page = request.args.get('page', 1, int)
        info = request.args.get('info', '', str)
        skip = limit * (page - 1)
        weekpasswd_db = db_name_conf()['weekpasswd_db']  # {"task_name": re.compile(info)}

        total = mongo_cli[weekpasswd_db].find({"task_name": re.compile(info)}).count()
        dict_resp = mongo_cli[weekpasswd_db].find({"task_name": re.compile(info)}).limit(limit).skip(skip).sort('date', -1)
        lists = []
        for item in dict_resp:
            item['_id'] = "%s" % item['_id']
            # item['task_id'] = "%s" % item['task_id']
            item['date'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item['date']))
            lists.append(item)
        response_data = self.wrap_json_response(data={"list": lists, "total": total}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    def delete(self):
        """
        删除检出记录
        ---
        tags:
        - 弱口令检测(auth_tester)
        parameters:
        - name: id
          in: query
          description: id
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        _id = request.args.get('id')
        weekpasswd_db = db_name_conf()['weekpasswd_db']
        dc = mongo_cli[weekpasswd_db].delete_one({"_id": ObjectId(_id)}).deleted_count
        if dc:
            response_data = self.wrap_json_response(data="success", code=ReturnCode.SUCCESS)
        else:
            response_data = self.wrap_json_response(errmsg="Failed Delete WeekPasswd Record.", code=ReturnCode.INTERVAL_SERVER_ERROR)
        return jsonify(response_data)
