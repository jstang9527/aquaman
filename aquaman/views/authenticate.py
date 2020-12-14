# -*- coding: utf-8 -*-
import json
import time
from flask import request, session, jsonify
from flask.views import MethodView
from utils.response import CommonResponseMixin, ReturnCode


# 未认证的
class AuthenticateView(MethodView, CommonResponseMixin):
    # 登录
    def post(self):
        """
        管理员登录
        ---
        tags:
        - 管理员接口
        parameters:
        - name: body
          in: body
          required: true
          schema:
            id: dto.authenticate_input
            properties:
              username:
                type: string
                description: 账户
              password:
                type: string
                description: 密码
        responses:
          '200':
            description: SUCCESS
            schema:
              id: dto.authenticate_output
              properties:
                errno:
                  type: integer
                  description: errno
                  default: 0
                errmsg:
                  type: string
                  description: response_message
                data:
                  type: object
                  description: response_data
                  properties:
                    token:
                      type: string
                      description: token
        """
        body_data = json.loads(request.get_data().decode())
        username = body_data['username']
        password = body_data['password']
        if not username or not password:
            response_data = self.wrap_json_response(errmsg="Lost require params of username or password !", code=ReturnCode.WRONG_PARAMS)
        elif username != "admin" or password != "123456":
            response_data = self.wrap_json_response(errmsg="Authentication Failed !!!", code=ReturnCode.BROKEN_AUTHORIZED_DATA)
        else:
            session['admin'] = 'A1akPTQJiz9wi9yo4rDz8ubM1b1'
            data = {"token": session['admin']}
            response_data = self.wrap_json_response(data=data, code=ReturnCode.SUCCESS)
        return jsonify(response_data)


# 已认证的
class AuthenticatedView(MethodView, CommonResponseMixin):
    # 用户信息
    def get(self):
        """
        账户信息
        ---
        tags:
        - 管理员接口
        responses:
          '200':
            description: SUCCESS
            schema:
              id: dto.authenticate_userinfo_output
              properties:
                data:
                  type: object
                  description: response_data
                  properties:
                    id:
                      type: integer
                      description: id
                    user_name:
                      type: string
                      description: user
                    login_time:
                      type: string
                      description: login_time
                    avatar:
                      type: string
                      description: avatar
                    introduction:
                      type: string
                      description: introduction
                    roles:
                      type: array
                      description: roles
                      items:
                        type: string
                errmsg:
                  type: string
                  description: response_message
                errno:
                  type: integer
                  description: errno
                  default: 0
        """
        if "admin" in session:
            if session['admin'] != '':
                data = {
                    "id": 1,
                    "user_name": "admin",
                    "login_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                    "avatar": "https://zan71.com/cdn-img/icon/avatar/tx.gif",
                    "introduction": "super administrator",
                    "roles": ["admin"]
                }
                response_data = self.wrap_json_response(data=data, code=ReturnCode.SUCCESS)
                return jsonify(response_data)

        response_data = self.wrap_json_response(code=ReturnCode.UNAUTHORIZED)
        return jsonify(response_data)

    # 修改用户信息(密码)
    def put(self):
        pass

    # 退出
    def post(self):
        """
        注销登录
        ---
        tags:
        - 管理员接口
        responses:
          '200':
            description: SUCCESS
            schema:
              type: dto.public_string_data_output
              $ref: '#/definitions/dto.public_string_data_output'
        """
        session['admin'] = ''
        response_data = self.wrap_json_response(code=ReturnCode.SUCCESS)
        return jsonify(response_data)
