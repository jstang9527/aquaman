# -*- coding: utf-8 -*-
import re
import os
import time
import json
from flask import request, jsonify
from flask.views import MethodView
from utils.response import CommonResponseMixin, ReturnCode
from aquaman.lib.mongo_db import db_name_conf, mongo_cli
from bson import ObjectId
from threading import Thread
from aquaman.modules.poc_vul.poc_scanner import PocsuiteScanner
from aquaman.modules.poc_vul.parse_plugin import parse_plugin
from application import settings
from werkzeug.utils import secure_filename
tasks_db = db_name_conf()['tasks_db']
vul_db = db_name_conf()['vul_db']
plugin_db = db_name_conf()['plugin_db']


class PocVulTaskView(MethodView, CommonResponseMixin):
    # 获取任务详情
    def get(self):
        """
        获取任务详情
        ---
        tags:
        - POC漏洞检测
        definitions:
        - schema:
            id: dao.pocvul_taskinfo
            properties:
              _id:
                type: string
              pluginid_list:
                type: array
                description: 插件ID列表
                items:
                  type: string
              task_name:
                type: string
                description: 任务名
              recursion:
                type: string
                description: 扫描周期(0,1,7,30)
              target_list:
                type: array
                description: 扫描目标
                items:
                  type: string
              status:
                type: string
                description: 任务状态
              create_at:
                type: string
                description: 最后扫描时间
              update_at:
                type: string
                description: 最后扫描时间
        - schema:
            id: dto.pocvul_taskinfo_output
            properties:
              data:
                type: dao.pocvul_taskinfo
                $ref: '#/definitions/dao.pocvul_taskinfo'
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
          description: 任务ID
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.auth_tester_taskinfo_output
              $ref: '#/definitions/dto.auth_tester_taskinfo_output'
        """
        _id = request.args.get('task_id')
        taskinfo = mongo_cli[tasks_db].find_one({"_id": ObjectId(_id)})
        taskinfo['_id'] = "%s" % taskinfo['_id']
        response_data = self.wrap_json_response(data=taskinfo, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    # 创建任务
    def post(self):
        """
        创建任务
        ---
        tags:
        - POC漏洞检测
        definitions:
        - schema:
            id: dto.pocvul_createtask_input
            properties:
              pluginid_list:
                type: array
                description: 插件ID列表
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
        parameters:
        - name: body
          in: body
          required: true
          schema:
            type: dto.pocvul_createtask_input
            $ref: '#/definitions/dto.pocvul_createtask_input'
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
        targets = []
        for t in body_data['target_list']:
            if t.strip():
                targets.append(t)
        plugins = []
        for pid in body_data['pluginid_list']:
            plugins.append('%s' % pid)

        if not plugins and not targets:
            return jsonify(self.wrap_json_response(errmsg='plugins or targets length is 0', code=ReturnCode.WRONG_PARAMS))

        task_data = {
            "portinfo_id": '',
            "task_name": time.strftime("%y%m%d", time.localtime()) + "_" + body_data['task_name'],
            "status": "New",
            "target_list": targets,
            "recursion": int(body_data['recursion']),
            "pluginid_list": plugins,
            "create_at": int(time.time()),
            "update_at": int(time.time())
        }

        task_id = mongo_cli[tasks_db].insert_one(task_data).inserted_id
        print "task_id", task_id
        if task_id:
            scanner = PocsuiteScanner(task_id)
            t1 = Thread(target=scanner.set_scanner, args=())
            t1.start()
            response_data = self.wrap_json_response(data={'task_id': '%s' % task_id}, code=ReturnCode.SUCCESS)
            print "success"
        else:
            response_data = self.wrap_json_response(code=ReturnCode.INTERVAL_SERVER_ERROR)
        return jsonify(response_data)

    # 修改任务
    def put(self):
        """
        更新任务
        ---
        tags:
        - POC漏洞检测
        definitions:
        - schema:
            id: dto.pocvul_puttask_input
            properties:
              id:
                type: string
                description: 任务ID
              pluginid_list:
                type: array
                description: 插件列表
                items:
                  type: string
              target_list:
                type: array
                description: 目标列表
                items:
                  type: string
              recursion:
                type: integer
                description: 任务执行周期(0/1/7/30),0为立即执行且仅执行一次
        parameters:
        - name: body
          in: body
          required: true
          schema:
            type: dto.pocvul_puttask_input
            $ref: '#/definitions/dto.pocvul_puttask_input'
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        body_data = json.loads(request.get_data().decode())
        task_id = body_data['id']
        targets = []
        for t in body_data['target_list']:
            if t.strip():
                targets.append(t)
        plugins = []
        for pid in body_data['plugins']:
            plugins.append('%s' % pid)
        task_info = {
            # "task_name": body_data['task_name'],  # 不可更改
            "recursion": int(body_data['recursion']),
            "target_list": targets,
            "pluginid_list": plugins
        }
        if mongo_cli[tasks_db].update_one({"_id": ObjectId(task_id)}, {"$set": task_info}).modified_count:
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
        - POC漏洞检测
        parameters:
        - name: id
          in: query
          description: 任务ID
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        task_id = request.args.get('id')
        if mongo_cli[tasks_db].delete_one({'_id': ObjectId(task_id)}).deleted_count:
            mongo_cli[vul_db].delete_many({'task_id': task_id})
            response_data = self.wrap_json_response(data='success', code=ReturnCode.SUCCESS)
        else:
            response_data = self.wrap_json_response(code=ReturnCode.RESOURCE_NOT_EXISTS)
        return jsonify(response_data)

    # 重新扫描, 删除旧信息
    def patch(self):
        """
        重新扫描
        ---
        tags:
        - POC漏洞检测
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
        task_id = request.args.get('id')
        if not task_id:
            response_data = self.wrap_json_response(errmsg="require task_id params", code=ReturnCode.WRONG_PARAMS)
            return jsonify(response_data)

        # 1.无需删除旧的检出信息
        # 2.更新任务状态
        dc = mongo_cli[tasks_db].update_one({"_id": ObjectId(task_id)}, {"$set": {
            "status": "Queued",
            "update_at": int(time.time()),
        }}).modified_count
        # 3.执行扫描
        if dc:
            scanner = PocsuiteScanner(task_id)
            t1 = Thread(target=scanner.set_scanner, args=())
            t1.start()
            response_data = self.wrap_json_response(data="success", code=ReturnCode.SUCCESS)
        else:
            response_data = self.wrap_json_response(errmsg="Failed Update TaskInfo.", code=ReturnCode.FAILED)
        return jsonify(response_data)


class PocVulTasksView(MethodView, CommonResponseMixin):
    # 获取任务列表
    def get(self):
        """
        获取任务列表
        ---
        tags:
        - POC漏洞检测
        definitions:
        - schema:
            id: dto.pocvul_tasklist_output
            properties:
              data:
                type: object
                description: 任务列表
                properties:
                  list:
                    type: array
                    description: 任务记录
                    items:
                      type: dao.pocvul_taskinfo
                      $ref: '#/definitions/dao.pocvul_taskinfo'
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
              type: dto.pocvul_tasklist_output
              $ref: '#/definitions/dto.pocvul_tasklist_output'
        """

        page_size = request.args.get('page_size', 10, int)
        page_no = request.args.get('page_no', 1, int)
        info = request.args.get('info', '', str)
        skip = page_size * (page_no - 1)
        total = mongo_cli[tasks_db].find({"task_name": re.compile(info)}).count()
        dict_resp = mongo_cli[tasks_db].find({"task_name": re.compile(info)}).limit(page_size).skip(skip).sort('update_at', -1)
        data = []
        for item in dict_resp:
            item['_id'] = "%s" % item['_id']
            item['create_at'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item['create_at']))
            item['update_at'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item['update_at']))
            data.append(item)
        response_data = self.wrap_json_response(data={'list': data, 'total': total}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)


class PocVulDetectView(MethodView, CommonResponseMixin):
    # 获取Poc检出列表
    def get(self):
        """
        获取检出列表
        ---
        tags:
        - POC漏洞检测
        definitions:
        - schema:
            id: dao.pocvul_detectinfo
            properties:
              _id:
                type: string
              date:
                type: string
                description: 检测日期
              hash:
                type: string
              plugin_app:
                type: string
              plugin_filename:
                type: string
                description: 插件脚本
              plugin_id:
                type: string
                description: 插件ID
              plugin_name:
                type: string
                description: 插件名
              plugin_type:
                type: string
                description: 插件类型
              plugin_version:
                type: string
                description: 插件版本
              scan_result:
                type: string
                description: 检测结果
              tag:
                type: string
              target:
                type: string
                description: 检测目标
              task_id:
                type: string
                description: 任务ID
              task_name:
                type: string
                description: 任务名
              poc_content:
                type: string
                description: poc漏洞脚本
        - schema:
            id: dto.pocvul_detectlist_output
            properties:
              data:
                type: object
                description: 任务列表
                properties:
                  list:
                    type: array
                    description: 任务记录
                    items:
                      type: dao.pocvul_detectinfo
                      $ref: '#/definitions/dao.pocvul_detectinfo'
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
              type: dto.pocvul_detectlist_output
              $ref: '#/definitions/dto.pocvul_detectlist_output'
        """
        page_size = request.args.get('page_size', 10, int)
        page_no = request.args.get('page_no', 1, int)
        info = request.args.get('info', '', str)
        skip = page_size * (page_no - 1)

        total = mongo_cli[vul_db].find({"tag": {"$ne": "delete"}, "task_name": re.compile(info)}).count()
        dict_resp = mongo_cli[vul_db].find({"tag": {"$ne": "delete"}, "task_name": re.compile(info)}).limit(page_size).skip(skip).sort('date', -1)
        data = []
        for item in dict_resp:
            item['_id'] = "%s" % item['_id']
            item['date'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item['date']))
            try:
                with open(item['plugin_filename']) as f:
                    item['poc_content'] = f.read()
                    f.close()
            except Exception:
                item['poc_content'] = '[*]file not found.'
            item['plugin_filename'] = item['plugin_filename'].split('/')[-1]
            data.append(item)
        response_data = self.wrap_json_response(data={'list': data, 'total': total}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    def delete(self):
        """
        删除检出记录(软删除)
        ---
        tags:
        - POC漏洞检测
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
        vul_info = mongo_cli[vul_db].find_one({"_id": ObjectId(_id)})
        if not vul_info:
            response_data = self.wrap_json_response(code=ReturnCode.RESOURCE_NOT_EXISTS)
            return jsonify(response_data)

        dc = mongo_cli[vul_db].update_one({"_id": ObjectId(_id)}, {"$set": {"tag": "delete"}}).modified_count
        if dc:
            response_data = self.wrap_json_response(code=ReturnCode.SUCCESS)
        else:
            response_data = self.wrap_json_response(errmsg='Failed Update Auth TaskInfo.', code=ReturnCode.FAILED)
        return jsonify(response_data)


class PocPluginView(MethodView, CommonResponseMixin):
    # 获取插件列表
    # 分页+查全部
    def get(self):
        """
        获取插件列表
        ---
        tags:
        - POC漏洞检测
        definitions:
        - schema:
            id: dao.pocvul_plugininfo
            properties:
              _id:
                type: string
              plugin_date:
                type: string
                description: 上传日期
              plugin_version:
                type: string
                description: 受影响版本
              plugin_app:
                type: string
                description: 受影响应用
              plugin_filename:
                type: string
                description: 插件脚本
              plugin_author:
                type: string
                description: 脚本作者
              plugin_name:
                type: string
                description: 插件名
              plugin_type:
                type: string
                description: 插件类型
        - schema:
            id: dto.pocvul_pluginlist_output
            properties:
              data:
                type: object
                description: 插件列表
                properties:
                  list:
                    type: array
                    items:
                      type: dao.pocvul_plugininfo
                      $ref: '#/definitions/dao.pocvul_plugininfo'
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
              type: dto.pocvul_pluginlist_output
              $ref: '#/definitions/dto.pocvul_pluginlist_output'
        """
        page_size = request.args.get('page_size', 10, int)
        page_no = request.args.get('page_no', 1, int)
        info = request.args.get('info', '', str)
        skip = page_size * (page_no - 1)

        total = mongo_cli[plugin_db].find({"plugin_name": re.compile(info)}).count()
        dict_resp = mongo_cli[plugin_db].find({"plugin_name": re.compile(info)}).limit(page_size).skip(skip).sort('date', -1)
        data = []
        for item in dict_resp:
            item['_id'] = "%s" % item['_id']
            item['plugin_filename'] = item['plugin_filename'].split('/')[-1]
            data.append(item)
        response_data = self.wrap_json_response(data={'list': data, 'total': total}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    # 上传插件
    def post(self):
        """
        上传POC插件
        ---
        tags:
        - POC漏洞检测
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        # 获取前端传输的文件(对象)
        f = request.files['file']
        # # secure_filename：检测中文是否合法
        filename = secure_filename(f.filename)
        # # 验证文件格式（简单设定几个格式）
        types = ['py']
        if filename.split('.')[-1] in types:
            # 保存图片
            try:
                filepath = settings.POC_FILEPATH + filename
                f.save(filepath)
                plugin_info = parse_plugin(filepath)
                if plugin_info:
                    mongo_cli[plugin_db].insert_one(plugin_info)
                    response_data = self.wrap_json_response(code=ReturnCode.SUCCESS)
                else:
                    os.remove(filepath)
                    response_data = self.wrap_json_response(errmsg="Failed Save Plugin In MongoDB.", code=ReturnCode.FAILED)
            except Exception as e:
                response_data = self.wrap_json_response(errmsg="Failed Save Plugin, info:%s" % e, code=ReturnCode.INTERVAL_SERVER_ERROR)
        else:
            response_data = self.wrap_json_response(errmsg="error types of file.", code=ReturnCode.WRONG_PARAMS)
        return jsonify(response_data)

    # 删除插件
    def delete(self):
        """
        删除POC插件
        ---
        tags:
        - POC漏洞检测
        parameters:
        - name: id
          in: query
          description: Plugin ID
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
        plugin_info = mongo_cli[plugin_db].find_one({"_id": ObjectId(_id)})
        if not plugin_info:
            response_data = self.wrap_json_response(code=ReturnCode.RESOURCE_NOT_EXISTS)
            return jsonify(response_data)

        try:
            filepath = plugin_info['plugin_filename']
            os.remove(filepath)
            count = mongo_cli[plugin_db].delete_one({"_id": ObjectId(_id)}).deleted_count
            if count == 1:
                response_data = self.wrap_json_response(data={"data": "success"}, code=ReturnCode.SUCCESS)
            else:
                response_data = self.wrap_json_response(code=ReturnCode.RESOURCE_NOT_EXISTS)
        except Exception as e:
            response_data = self.wrap_json_response(errmsg="%s" % e, code=ReturnCode.RESOURCE_NOT_EXISTS)
        return jsonify(response_data)


# [-]
class PocCodeView(MethodView, CommonResponseMixin):
    def get(self):
        """
        获取POC脚本代码
        ---
        tags:
        - POC漏洞检测
        parameters:
        - name: id
          in: query
          description: Plugin ID
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
        info = mongo_cli[plugin_db].find_one({"_id": ObjectId(_id)})
        fpath = info['plugin_filename']
        try:
            with open(fpath) as f:
                content = f.read()
                response_data = self.wrap_json_response(data={'data': content}, code=ReturnCode.SUCCESS)
        except Exception as e:
            response_data = self.wrap_json_response(errmsg="%s" % e, code=ReturnCode.RESOURCE_NOT_EXISTS)
        return jsonify(response_data)
