# -*- coding: utf-8 -*-
import re
from flask import jsonify, request
from flask.views import MethodView
from utils.response import CommonResponseMixin, ReturnCode
from aquaman.lib.mongo_db import mongo_cli, db_name_conf
from bson import ObjectId

server_db = db_name_conf()['server_db']


# 资产信息
class AssetInfoView(CommonResponseMixin, MethodView):
    # 获取资产详情
    def get(self):
        """
        获取资产详情
        ---
        tags:
        - 资产管理
        definitions:
        - schema:
            id: dto.assetinfo_output
            properties:
              data:
                type: dao.asset_info
                $ref: '#/definitions/dao.asset_info'
                description: response_data
              errmsg:
                type: string
                description: errno
              errno:
                type: integer
                description: errno
                default: 0
        parameters:
        - name: server_id
          in: query
          description: 资产ID
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.assetinfo_output
              $ref: '#/definitions/dto.assetinfo_output'
        """
        server_id = request.args.get('server_id')
        data = mongo_cli[server_db].find_one({'_id': ObjectId(server_id)})
        data['_id'] = "%s" % data['_id']
        response_data = self.wrap_json_response(data=data, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    # 添加资产
    def post(self):
        response_data = self.wrap_json_response(data="success", code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    # 删除资产
    def delete(self):
        """
        删除资产信息记录
        ---
        tags:
        - 资产管理
        parameters:
        - name: server_id
          in: query
          description: server_id
          required: true
          type: string
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        server_id = request.args.get('server_id')
        if mongo_cli[server_db].delete_one({'_id': ObjectId(server_id)}):
            response_data = self.wrap_json_response(data="success", code=ReturnCode.SUCCESS)
        else:
            response_data = self.wrap_json_response(code=ReturnCode.INTERVAL_SERVER_ERROR)
        return jsonify(response_data)


class AssetInfoListView(CommonResponseMixin, MethodView):
    # 资产列表分页查询
    def get(self):
        """
        获取资产列表
        ---
        tags:
        - 资产管理
        definitions:
        - schema:
            id: dao.asset_info
            properties:
              _id:
                type: string
              asset_name:
                type: string
                description: 资产名
              scan_node:
                type: string
              plugin_app:
                type: string
              ip:
                type: string
                description: 资产地址
              cdn:
                type: string
              extrabanner:
                type: string
              port_info:
                type: array
                description: 变更额外出现port_info_2字段, type=list;
                items:
                  type: object
                  description: 端口信息
                  properties:
                    cpe:
                      type: string
                    extrainfo:
                      type: string
                    host:
                      type: string
                    name:
                      type: string
                    port:
                      type: integer
                    product:
                      type: string
                    script:
                      type: string
                    updatetime:
                      type: string
                    version:
                      type: string
              task_type:
                type: string
              title:
                type: string
                description: 网站title
              waf:
                type: string
              asset_cus_id:
                type: string
              state:
                type: string
              asset_cus_name:
                type: string
                description: 隶属客户
              ip_info:
                type: array
                description: IP信息列表
                items:
                  type: object
                  description: IP信息
                  properties:
                    area:
                      type: string
                    gps:
                      type: string
                    isp:
                      type: string
              hash:
                type: string
              site_info:
                type: string
              asset_name:
                type: string
              httpserver:
                type: string
              banner:
                type: string
              scan_times:
                type: integer
              asset_task_id:
                type: string
              updatetime:
                type: string
              target:
                type: string
              os:
                type: string
              cdn_cname:
                type: string
              xpb:
                type: string
              cms:
                type: string
              ports:
                type: array
                description: 变更额外出现ports_2字段, type=list;
                items:
                  type: integer
        - schema:
            id: dto.asset_infolist_output
            properties:
              data:
                type: object
                description: 任务列表
                properties:
                  list:
                    type: array
                    description: 任务记录
                    items:
                      type: dao.asset_info
                      $ref: '#/definitions/dao.asset_info'
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
          description: asset_name
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
              type: dto.asset_infolist_output
              $ref: '#/definitions/dto.asset_infolist_output'
        """
        page_size = request.args.get('page_size', 10, int)
        page_no = request.args.get('page_no', 1, int)
        info = request.args.get('info', '', str)
        skip = page_size * (page_no - 1)

        total = mongo_cli[server_db].find({"tag": {"$ne": "delete"}, "asset_name": re.compile(info)}).count()
        dict_resp = mongo_cli[server_db].find({"tag": {"$ne": "delete"}, "asset_name": re.compile(info)}).limit(page_size).skip(skip).sort('updatetime', -1)
        data = []
        for item in dict_resp:
            item['_id'] = "%s" % item['_id']
            if not item['ip_info']:
                item['ip_info'] = [{"area": "Unkown", "gps": "Unkown", "isp": "Unkown"}]
            if not item['port_info']:
                item['port_info'] = [{"cpe": "", "extrainfo": "", "host": "", "name": "", "port": 0, "product": "", "script": {}, "updatetime": "", "version": ""}]
            data.append(item)

        response_data = self.wrap_json_response(data={'list': data, 'total': total}, code=ReturnCode.SUCCESS)
        return jsonify(response_data)
