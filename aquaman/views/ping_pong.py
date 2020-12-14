# coding=utf-8
import json
from flask import request, jsonify
from flask.views import MethodView
from utils.response import CommonResponseMixin, ReturnCode


# 用于web初始化测试
class TestAPI(MethodView, CommonResponseMixin):
    def get(self):
        """
        Web测试GET API
        ---
        tags:
        - Testing
        definitions:
        - schema:
            id: WebTest
            properties:
              data:
                  type: object
                  description: response_data
                  properties:
                    name:
                      type: string
                      description: data_name
                    time:
                      type: string
                      description: data_time
                    uri_data:
                      type: object
                      description: client_request_uri
                      properties:
                        key:
                          type: string
              errmsg:
                type: string
                description: errmsg
              errno:
                type: integer
                description: errno
                default: 0
        parameters:
        - name: key
          in: query
          description: any content
          required: false
          type: string
          default: hello flask!
        responses:
          '200':
            description: SUCCESS
            schema:
              type: WebTest
              $ref: '#/definitions/WebTest'
        """
        uri_data = request.args.to_dict()
        data = {"name": "Get Aquaman", "time": "2020-09-24", "uri_data": uri_data}
        response_data = self.wrap_json_response(data=data, code=ReturnCode.SUCCESS)
        return jsonify(response_data)

    def post(self):
        """
        Web测试POST API
        ---
        tags:
        - Testing
        parameters:
        - name: body
          in: body
          description: Sent from-data to server from client
          required: false
          type: object
          properties:
            name:
              type: string
              description: data_name
        responses:
          '200':
            description: SUCCESS
            schema:
              type: WebTest
              $ref: '#/definitions/WebTest'
        """
        post_data = json.loads(request.get_data().decode())
        data = {"name": "Post Aquaman", "time": "2020-09-24", "post_data": post_data}
        response_data = self.wrap_json_response(data=data, code=ReturnCode.SUCCESS)
        return jsonify(response_data)
