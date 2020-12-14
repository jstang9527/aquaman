# coding=utf-8
import re
from utils.response import CommonResponseMixin, ReturnCode
from flask.views import MethodView
from flask import jsonify, request
from aquaman.lib.mongo_db import db_name_conf, mongo_cli
from bson import ObjectId
from aquaman.modules.web_vul.awvs_api import AcunetixScanner
import ast

portinfo_db = db_name_conf()['portinfo_db']
exploit_db = db_name_conf()['exploit_db']


class ServiceInfoView(CommonResponseMixin, MethodView):
    # 获取端口服务漏洞详情
    def get(self):
        """
        # 获取端口服务漏洞详情
        ---
        tags:
        - 服务发现
        definitions:
        - schema:
            id: dao.pocvul_taskinfo
            properties:
              _id:
                type: string
              start_date:
                type: string
                description: 起始日期
              plugin_id:
                type: array
                description: 插件ID列表
                items:
                  type: string
              task_name:
                type: string
                description: 任务名
              task_recursion:
                type: string
                description: 扫描周期(0,1,7,30)
              scan_target:
                type: array
                description: 扫描目标
                items:
                  type: string
              end_date:
                type: string
                description: 最后扫描时间
              task_status:
                type: string
                description: 任务状态
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
        - name: portinfo_id
          in: query
          description: 服务端口ID
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.auth_tester_taskinfo_output
              $ref: '#/definitions/dto.auth_tester_taskinfo_output'
        """
        _id = request.args.get('portinfo_id')
        info = mongo_cli[portinfo_db].find_one({"_id": ObjectId(_id)})
        info['_id'] = "%s" % info['_id']
        result = []
        if 'vul_type' not in info.keys():
            print "info['vul_type'] == 'exploit':"
            info['vulnerabilities'] = result
        # 再把对应的漏洞信息打出来
        elif info['vul_type'] == 'web':
            print "info['vul_type'] == 'exploit':"
            scan_id = info['scan_id']
            awvs_scan = AcunetixScanner()
            resp = awvs_scan.get_scaninfo(scan_id)
            scan_session_id = resp['current_session']['scan_session_id']
            if scan_session_id:
                resp = awvs_scan.get_vullist(scan_id, scan_session_id)
                for vuln in resp['vulnerabilities']:
                    detail = awvs_scan.get_vuldetail(scan_id, scan_session_id, vuln['vuln_id'])
                    if not detail:
                        continue
                    result.append({
                        'affects_url': re.sub('http://.*?/', '/', detail['affects_url']), 'vt_name': detail['vt_name'],
                        'description': re.sub('<.*?>', '', detail['description']), 'payload': detail['request'],
                        'exploit': detail['source'], 'impact': detail['impact'], 'tags': detail['tags'],
                        'attack_result': re.sub('<.*?>', '', detail['details']), 'method': 'Web Crawler',  # [todo] 识别方法
                        'severity': detail['severity']
                    })
            info['vulnerabilities'] = result

        elif info['vul_type'] == 'exploit':
            print "info['vul_type'] == 'exploit':"
            for vuln_info in info['vulnerabilities']:
                result.append({
                    'vt_name': vuln_info['vt_name'],
                    'exploit': vuln_info['exploit'], 'payload': vuln_info['payload'],
                    'cmd': vuln_info['cmd'], 'description': vuln_info['desc'],
                    'attack_result': vuln_info['verify'], 'method': 'exploit',  # [todo] 识别方法
                })
            info['vulnerabilities'] = result
        # print info
        elif info['vul_type'] == 'pocsuite':
            print "info['vul_type'] == 'pocsuite'"
            for vuln_info in info['vulnerabilities']:
                file_path = vuln_info['plugin_filename']
                poc_content = ''
                try:
                    with open(file_path) as f:
                        poc_content = f.read()
                except Exception as e:
                    poc_content = "%s" % e

                try:
                    attack_result = ast.literal_eval(vuln_info['attack_result'])
                except Exception:
                    attack_result = vuln_info['attack_result']

                result.append({
                    'vt_name': vuln_info['vt_name'],
                    'plugin_type': vuln_info['plugin_type'],
                    'plugin_id': vuln_info['plugin_id'],
                    'plugin_filename': vuln_info['plugin_filename'],
                    'description': vuln_info['description'],
                    'attack_result': attack_result,
                    'poc': poc_content
                })
            info['vulnerabilities'] = result
        print info
        response_data = self.wrap_json_response(data=info, code=ReturnCode.SUCCESS)
        return jsonify(response_data)


class ServiceInfoListView(CommonResponseMixin, MethodView):
    def get(self):
        """
        服务列表
        ---
        tags:
        - 服务发现
        definitions:
        - schema:
            id: dao.service_info
            properties:
              _id:
                type: string
              instance_id:
                type: string
              product:
                type: string
              state:
                type: string
              version:
                type: string
              protocol:
                type: string
              name:
                type: string
              conf:
                type: string
              reason:
                type: string
              extrainfo:
                type: string
              port:
                type: string
              cpe:
                type: string
              vul_id:
                type: string
        - schema:
            id: dto.service_infolist_output
            properties:
              data:
                type: object
                description: 服务列表
                properties:
                  list:
                    type: array
                    items:
                      type: dao.service_info
                      $ref: '#/definitions/dao.service_info'
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
          description: 实例ID
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
              type: dto.service_infolist_output
              $ref: '#/definitions/dto.service_infolist_output'
        """
        page_size = request.args.get('page_size', 10, int)
        page_no = request.args.get('page_no', 1, int)
        info = request.args.get('info', '', str)
        skip = page_size * (page_no - 1)
        total = mongo_cli[portinfo_db].find({"instance_id": re.compile(info)}).count()
        dict_resp = mongo_cli[portinfo_db].find({"instance_id": re.compile(info)}).limit(page_size).skip(skip).sort('create_at', -1)
        data = []
        awvs_scan = AcunetixScanner()
        for item in dict_resp:
            item['_id'] = "%s" % item['_id']
            if 'vul_type' in item.keys() and item['vul_type'] == 'web':
                # 从AWVS API 拿数据
                resp = awvs_scan.get_scaninfo(item['scan_id'])
                scan_session_id = resp['current_session']['scan_session_id']
                if scan_session_id:
                    resp = awvs_scan.get_vullist(scan_id=item['scan_id'], scan_session_id=scan_session_id)
                    item['vulnerabilities'] = resp['vulnerabilities']
            elif 'vul_type' in item.keys() and item['vul_type'] == 'exploit':
                if not item['vulnerabilities']:
                    item['vulnerabilities'] = []
            else:
                item['vulnerabilities'] = []
            data.append(item)

        response_data = self.wrap_json_response(data={'list': data, 'total': total}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)


# 根据端口信息ID获取对应的渗透方法
class InfiltrationToolView(CommonResponseMixin, MethodView):
    def get(self):
        """
        # 获取服务采用的渗透工具
        ---
        tags:
        - 服务发现
        definitions:
        - schema:
            id: dao.infiltration_tool_info
            properties:
              _id:
                type: string
              start_date:
                type: string
                description: 起始日期
              plugin_id:
                type: array
                description: 插件ID列表
                items:
                  type: string
              task_name:
                type: string
                description: 任务名
              task_recursion:
                type: string
                description: 扫描周期(0,1,7,30)
              scan_target:
                type: array
                description: 扫描目标
                items:
                  type: string
              end_date:
                type: string
                description: 最后扫描时间
              task_status:
                type: string
                description: 任务状态
        - schema:
            id: dto.infiltration_tool_info_output
            properties:
              data:
                type: dao.infiltration_tool_info
                $ref: '#/definitions/dao.infiltration_tool_info'
                description: response_data
              errmsg:
                type: string
                description: errno
              errno:
                type: integer
                description: errno
                default: 0
        parameters:
        - name: portinfo_id
          in: query
          description: 服务端口ID
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.infiltration_tool_info_output
              $ref: '#/definitions/dto.infiltration_tool_info_output'
        """
        # [*] 有可能是AWVS、POC插件、Exploit等
        # [*] 所以需要分别查库进行输出

        _ = {
            "_id": "",
            "service": "ftp",
            "app": "vsftpd",
            "version": "2.3.4",
            "exploit": "unix/ftp/vsftpd_234_backdoor",
            "payload": "cmd/unix/interact",
            "cmd": "uptime",
            "desc": "",
            "create_at": "",
            "update_at": "",
            "is_delete": 0,
        }
        a_result = {
            "method": "Awvs API Scan"
        }
        # 0.先把portinfo信息查出来
        _id = request.args.get('portinfo_id')
        info = mongo_cli[portinfo_db].find_one({"_id": ObjectId(_id)})
        info['_id'] = "%s" % info['_id']
        # 1.再把对应的漏洞信息打出来
        # [todo] web类的需要调POC插件(xss、sql)打
        if info['vul_type'] == 'web':
            # 简略写, 因为AWVS也没输出是用什么打的
            response_data = self.wrap_json_response(data=a_result)
        # print info
        response_data = self.wrap_json_response(data=info, code=ReturnCode.SUCCESS)
        return jsonify(response_data)
