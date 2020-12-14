# coding=utf-8
import json
from flask import jsonify, request
from flask.views import MethodView
from aquaman.lib.mongo_db import db_name_conf, mongo_cli
from application import settings
from utils.response import CommonResponseMixin, ReturnCode

config_db = db_name_conf()['config_db']


class SysConfig(MethodView, CommonResponseMixin):
    def get(self):
        """
        系统数据
        ---
        tags:
        - 系统设置
        definitions:
        - schema:
            id: dao.system_config_info
            properties:
              _id:
                type: string
              config_name:
                type: integer
                description: 配置名
              poc_thread:
                type: integer
                description: Poc线程扫描数
              port_thread:
                type: integer
                description: 端口扫描线程数
              auth_tester_thread:
                type: integer
                description: 认证爆破线程数
              discovery_thread:
                type: integer
                description: 资产发现线程数
              subdomain_thread:
                type: integer
                description: 域名爆破线程数
              discovery_time:
                type: string
                description: 资产发现时间
              poc_frequency:
                type: integer
                description: Poc检测频率
              subdomain_dict_2:
                type: array
                description: 二级子域名列表
                items:
                  type: string
              subdomain_dict_3:
                type: array
                description: 三级子域名列表
                items:
                  type: string
              port_list:
                type: array
                description: 端口列表
                items:
                  type: integer
              auth_service:
                type: array
                description: 服务爆破列表
                items:
                  type: string
              username_dict:
                type: array
                description: 账户字典
                items:
                  type: string
              password_dict:
                type: array
                description: 密码字典
                items:
                  type: string
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
        # connectiondb(config_db).insert_one({"config_name": config_name})
        config_info = mongo_cli[config_db].find_one({"config_name": settings.CONFIG_NAME})
        config_info['_id'] = "%s" % config_info['_id']
        response_data = self.wrap_json_response(data=config_info, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    def put(self):
        """
        更新系统设置
        ---
        tags:
        - 系统设置
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
            type: dao.system_config_info
            $ref: '#/definitions/dao.system_config_info'
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        body_data = json.loads(request.get_data().decode())
        mongo_cli[config_db].find_one_and_update({"config_name": settings.CONFIG_NAME}, {"$set": {
            # "_id": body_data['_id'],  # "5c483205cc599e1032f2a6fb"
            "auth_service": body_data['auth_service'],  # Array[42],
            "auth_tester_thread": body_data['auth_tester_thread'],  # 50,
            # "config_name": body_data['config_name'],  # "mars",
            "discovery_thread": body_data['discovery_thread'],  # 50,
            "discovery_time": body_data['discovery_time'],  # "10:30:00",
            "password_dict": body_data['password_dict'],  # Array[8],
            "poc_frequency": body_data['poc_frequency'],  # 15,
            "poc_thread": body_data['poc_thread'],  # 50,
            "port_list": body_data['port_list'],  # Array[34],
            "port_thread": body_data['port_thread'],  # 50,
            "subdomain_dict_2": body_data['subdomain_dict_2'],  # Array[3],
            "subdomain_dict_3": body_data['subdomain_dict_3'],  # Array[3],
            "subdomain_thread": body_data['subdomain_thread'],  # 50,
            "username_dict": body_data['username_dict'],  # Array[8]
        }})
        return jsonify(self.wrap_json_response(code=ReturnCode.SUCCESS))
