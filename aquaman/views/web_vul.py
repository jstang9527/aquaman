# coding=utf-8
import re
import json
import time
from flask import request, jsonify
from flask.views import MethodView
from utils.response import CommonResponseMixin, ReturnCode
from aquaman.lib.mongo_db import db_name_conf, mongo_cli
from bson import ObjectId
from utils.public import parse_target
from aquaman.modules.web_vul.awvs_api import AcunetixScanner

vulscan_db = db_name_conf()['vulscan_db']  # 存储AWVS任务的


class WebVulTasksView(MethodView, CommonResponseMixin):
    # 获取任务列表
    def get(self):
        """
        任务列表, 刷新部分任务状态
        ---
        tags:
        - Web漏洞检测
        definitions:
        - schema:
            id: dto.webvul_tasklist_output
            properties:
              data:
                type: object
                description: 任务列表
                properties:
                  list:
                    type: array
                    description: 任务记录
                    items:
                      type: dao.webvul_taskinfo
                      $ref: '#/definitions/dao.webvul_taskinfo'
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
          description: task_name
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
              type: dto.webvul_tasklist_output
              $ref: '#/definitions/dto.webvul_tasklist_output'
        """
        limit = request.args.get('limit', 10, int)
        page = request.args.get('page', 1, int)
        info = request.args.get('info', '', str)
        skip = limit * (page - 1)
        total = mongo_cli[vulscan_db].find({"task_name": re.compile(info)}).count()
        dict_resp = mongo_cli[vulscan_db].find({"task_name": re.compile(info)}).limit(limit).skip(skip).sort('date', -1)

        lists = []
        for item in dict_resp:
            item['_id'] = "%s" % item['_id']
            item['date'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item['date']))
            lists.append(item)

        response_data = self.wrap_json_response(data={'list': lists, 'total': total}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)


class WebVulTaskView(MethodView, CommonResponseMixin):
    # 获取任务详情
    def get(self):
        """
        获取任务详情
        ---
        tags:
        - Web漏洞检测
        definitions:
        - schema:
            id: dao.webvul_taskinfo
            properties:
              target_id:
                type: array
                description: 目标ID
                items:
                  type: string
              target_list:
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
              status:
                type: string
                description: 执行状态
              scan_type:
                type: string
                description: 扫描类型
              date:
                type: string
                description: 扫描日期
              description:
                type: string
                description: 描述
        - schema:
            id: dto.webvul_taskinfo_output
            properties:
              data:
                type: dao.webvul_taskinfo
                $ref: '#/definitions/dao.webvul_taskinfo'
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
              type: dto.webvul_taskinfo_output
              $ref: '#/definitions/dto.webvul_taskinfo_output'
        """
        task_id = request.args.get('task_id')
        if not task_id:
            response_data = self.wrap_json_response(errmsg="Lost query params of task_id", code=ReturnCode.WRONG_PARAMS)
            return jsonify(response_data)

        dict_result = mongo_cli[vulscan_db].find_one({"_id": ObjectId(task_id)})
        dict_result['_id'] = "%s" % dict_result['_id']
        response_data = self.wrap_json_response(data=dict_result, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    # 创建任务
    def post(self):
        """
        创建任务
        ---
        tags:
        - Web漏洞检测
        definitions:
        - schema:
            id: dto.webvul_task_input
            properties:
              target_list:
                type: array
                description: 目标列表
                items:
                  type: string
              scan_type:
                type: string
                description: 扫描类型(0-完全扫描,1,2,3,4,5)
                default: 0
              task_name:
                type: string
                description: 任务名
              description:
                type: string
                description: 备注
        parameters:
        - name: body
          in: body
          required: true
          schema:
            type: dto.webvul_task_input
            $ref: '#/definitions/dto.webvul_task_input'
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
        task_name = body_data['task_name']
        target_list = body_data['target_list']
        scan_type = body_data['scan_type']
        description = body_data['description']
        target_id = []
        for target in parse_target(target_list):
            if 'http' not in target:
                target = 'http://' + target
            scan_dict = AcunetixScanner().start_task(target, description, scan_type)
            if not scan_dict:
                response_data = self.wrap_json_response(code=ReturnCode.INTERVAL_SERVER_ERROR)
                return jsonify(response_data)
            target_id.append(scan_dict['target_id'])
        task_data = {
            "task_name": task_name,
            "target_list": target_list,
            "scan_type": scan_type,
            "description": description,
            "status": "",
            "target_id": target_id,
            "date": int(time.time()),
        }
        task_id = mongo_cli[vulscan_db].insert_one(task_data).inserted_id
        response_data = self.wrap_json_response(data={"task_id": "%s" % task_id}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    # 删除任务
    def delete(self):
        """
        删除任务
        ---
        tags:
        - Web漏洞检测
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
            return jsonify(self.wrap_json_response(errmsg="Lost query params of task_id", code=ReturnCode.WRONG_PARAMS))

        awvs_scan = AcunetixScanner()
        webvulns = awvs_scan.get_all()
        target_id = mongo_cli[vulscan_db].find_one({"_id": ObjectId(task_id)})['target_id']
        if not mongo_cli[vulscan_db].remove({"_id": ObjectId(task_id)}):
            return jsonify(self.wrap_json_response(errmsg="Failed remove record from mongo", code=ReturnCode.RESOURCE_NOT_EXISTS))

        for item_id in target_id:
            awvs_scan.delete_target(item_id)
            for vuln in webvulns:
                if vuln['target_id'] != target_id:
                    continue
                awvs_scan.delete_scan(vuln['scan_id'])

        return jsonify(self.wrap_json_response(data="success", code=ReturnCode.SUCCESS))


class WebVulDetectList(MethodView, CommonResponseMixin):
    # 获取站点检出列表, 简略信息
    def get(self):
        """
        获取站点检出列表
        ---
        tags:
        - Web漏洞检测
        definitions:
        - schema:
            id: dao.webvul_detectinfo
            properties:
              address:
                type: string
                description: 目标站点
              desc:
                type: string
                description: 描述备注
              profile_name:
                type: string
                description: 扫描类型
              scan_id:
                type: string
                description: 站点扫描ID
              scan_session_id:
                type: string
              status:
                type: string
                description: 执行状态
              target_id:
                type: string
                description: 目标ID
              start_date:
                type: string
                description: 扫描日期
              vul_high:
                type: integer
                description: 高危
              vul_medium:
                type: integer
                description: 中危
              vul_low:
                type: integer
                description: 低危
              vul_info:
                type: integer
                description: 消息
        - schema:
            id: dto.webvul_detectlist_output
            properties:
              data:
                type: object
                description: 任务列表
                properties:
                  list:
                    type: array
                    description: 任务记录
                    items:
                      type: dao.webvul_detectinfo
                      $ref: '#/definitions/dao.webvul_detectinfo'
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
              type: dto.webvul_detectlist_output
              $ref: '#/definitions/dto.webvul_detectlist_output'
        """
        page_size = request.args.get('page_size', 10, int)
        page_no = request.args.get('page_no', 1, int)
        info = request.args.get('info', '', str)  # 根据task_id找对应的target_id
        skip = page_size * (page_no - 1)

        try:
            records = AcunetixScanner().get_all()
        except Exception as e:
            print(e)
            records = []
        if info:
            task_info = mongo_cli[vulscan_db].find_one({"_id": ObjectId(info)})
            list_result = []
            if task_info:
                for tid in task_info['target_id']:
                    for record in records:
                        if tid == record['target_id']:
                            list_result.append(record)
                data = list_result[skip: skip + page_size]
                total = len(list_result)
            else:
                data = []
                total = 0
        else:
            data = records[skip: skip + page_size]
            total = len(records)
        response_data = self.wrap_json_response(data={'list': data, 'total': total}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)


class WebVulDetect(MethodView, CommonResponseMixin):
    # 获取站点检出详情, 详细检出信息
    def get(self):
        """
        获取站点检出详情, 详细检出信息
        ---
        tags:
        - Web漏洞检测
        definitions:
        - schema:
            id: dao.webvul_detect_info
            properties:
              status:
                type: string
              vuln_list:
                type: array
                description: 漏洞列表 #细粒度todo
                items:
                  type: string
              scan_id:
                type: string
              vul_info:
                type: integer
              vul_high:
                type: integer
              vul_medium:
                type: integer
              vul_low:
                type: integer
              target_id:
                type: string
              start_date:
                type: string
              profile_name:
                type: string
              address:
                type: string
              scan_session_id:
                type: string
              desc:
                type: string
        - schema:
            id: dto.webvul_detect_info_output
            properties:
              data:
                type: dao.webvul_detect_info
                $ref: '#/definitions/dao.webvul_detect_info'
                description: response_data
              errmsg:
                type: string
                description: errno
              errno:
                type: integer
                description: errno
                default: 0
        parameters:
        - name: scan_id
          in: query
          description: scan_id
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.webvul_detect_info_output
              $ref: '#/definitions/dto.webvul_detect_info_output'
        """
        scan_id = request.args.get('scan_id')
        AS = AcunetixScanner()
        record = AS.get_scaninfo(scan_id=scan_id)
        if not record:
            return jsonify(self.wrap_json_response(data=ReturnCode.RESOURCE_NOT_EXISTS))

        scan_session_id = record['scan_session_id']
        vuln_list = AS.get_vullist(scan_id=scan_id, scan_session_id=scan_session_id)

        record['vuln_list'] = vuln_list['vulnerabilities']

        response_data = self.wrap_json_response(data=record, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    def delete(self):
        """
        删除检出记录
        ---
        tags:
        - Web漏洞检测
        parameters:
        - name: scan_id
          in: query
          description: scan_id
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        response_data = self.wrap_json_response(code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    def patch(self):
        """
        导出报告
        ---
        tags:
        - Web漏洞检测
        definitions:
        - schema:
            id: dto.webvul_report_output
            properties:
              data:
                type: object
                description: 报告种类
                properties:
                  html_url:
                    type: string
                  pdf_url:
                    type: string
              errmsg:
                type: string
                description: errno
              errno:
                type: integer
                description: errno
                default: 0
        parameters:
        - name: scan_id
          in: query
          description: scan_id
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.webvul_report_output
              $ref: '#/definitions/dto.webvul_report_output'
        """
        scan_id = request.args.get('scan_id')
        id_list = []
        id_list.append(scan_id)
        report_url = AcunetixScanner().reports(id_list, 'scans', scan_id)
        if report_url:
            response_data = self.wrap_json_response(data={"html_url": report_url[0], "pdf_url": report_url[1]}, code=ReturnCode.SUCCESS)
        else:
            response_data = self.wrap_json_response(code=ReturnCode.RESOURCE_NOT_EXISTS)
        return jsonify(response_data)
