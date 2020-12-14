# coding=utf-8
# description: 对单个服务仅需爆破
import os
import re
import time
import shlex
import signal
import string
from random import sample
from subprocess import Popen, PIPE


class HydraScanner:
    def __init__(self, target_list, service, username_list, password_list, args):
        self.target_list = target_list
        self.service = service  # 单个服务
        self.username_list = username_list
        self.password_list = password_list
        self.args = args
        self.dict_path = '/tmp/hydra_dict_' + ''.join(sample(string.ascii_letters + string.digits, 8))
        self.target_path = '/tmp/hydra_target_' + ''.join(sample(string.ascii_letters + string.digits, 8))
        self.stdout = ''
        self.stderr = ''
        self.result = []

    def _format_args(self):
        # 生成目标文件
        with open(self.target_path, 'w') as target_file:
            for target in self.target_list:
                target_file.write(target + "\n")

        # 某些服务仅需密码,有些服务均需要用户与密码
        if self.service in ['redis', 'cisco', 'oracle-listener', 's7-300', 'snmp', 'vnc']:
            with open(self.dict_path, 'w') as dict_file:
                for password in self.password_list:
                    dict_file.write(password + "\n")
            command = 'hydra -w 30 -t 4 %s -P %s -M %s %s' % (self.args, self.dict_path, self.target_path, self.service)
        else:
            with open(self.dict_path, 'w') as dict_file:
                for username in self.username_list:
                    for password in self.password_list:
                        dict_file.write(username + ':' + password + '\n')
            command = 'hydra -w 30 -t 4 %s -C %s -M %s %s' % (self.args, self.dict_path, self.target_path, self.service)
        return shlex.split(command)  # ['hydra', '-w', '15', '-l', 'None', '-p', 'None', 'ssh://172.31.50.156']

    def _format_resp(self):
        result_list = []
        pattern_res = r'(\[\d+\]\[%s\]\shost:\s.*?)\n' % self.service
        pattern_ip = r'host:\s(\d+\.\d+\.\d+\.\d+)\s'
        pattern_domain = r'host:\s([a-z.]+)\s'
        pattern_username = r'login:\s(.+?)\s+password:'
        pattern_password = r'password:\s(.+?)$'
        re_result = re.findall(pattern_res, self.stdout)
        for res in re_result:
            try:
                if re.findall(pattern_ip, res):
                    host = re.findall(pattern_ip, res)[0]
                elif re.findall(pattern_domain, res):
                    host = re.findall(pattern_domain, res)[0]
                else:
                    host = 'None'
                if re.findall(pattern_username, res):
                    username = re.findall(pattern_username, res)[0]
                else:
                    username = 'None'
                if re.findall(pattern_password, res):
                    password = re.findall(pattern_password, res)[0]
                else:
                    password = 'None'
                result = {
                    'target': host, 'service': self.service, 'username': username, 'password': password,
                    'payload': 'hydra -w 30 -t 4 %s -l %s -p %s %s' % (self.args, username, password, self.service),
                }
                result_list.append(result)
            except Exception as e:
                print res, e
        print "result_list", result_list
        return result_list

    def run(self):
        command = self._format_args()
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        try:
            (self.stdout, self.stderr) = process.communicate()
        except Exception as e:
            print process.pid, e
        finally:
            if os.path.exists(self.dict_path):
                os.remove(self.dict_path)
            if os.path.exists(self.target_path):
                os.remove(self.target_path)
        return self._format_resp()


class ServiceCheck:
    def __init__(self, target, service, args):
        self.target = target
        self.service = service
        self.args = args
        self.username = 'None'
        self.password = 'None'
        self.stdout = ''
        self.stderr = ''
        self.flag_list = ['Anonymous success', 'not require password']

    def run(self):
        command = self._format_args()
        start_time = time.time()
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        try:
            while process.poll() is None:
                if (time.time() - start_time).seconds > 15:
                    try:
                        os.kill(process.pid, signal.SIGTERM)
                    except OSError as e:
                        print(process.pid, e)
                    return False
            (self.stdout, self.stderr) = process.communicate()
        except Exception as e:
            print(process.pid, e)
        return self.host_check()

    def _format_args(self):
        if self.service in ['redis', 'cisco', 'oracle-listener', 's7-300', 'snmp', 'vnc']:
            # hydra -w 30 -p 123456 redis://192.168.1.1
            command = 'hydra -w 30 %s -p %s %s://%s' % (self.args, self.password, self.service, self.target)
        else:
            # hydra -w 30 -l root -p 123456 mysql://192.168.1.1
            command = 'hydra -w 30 %s -l %s -p %s %s://%s' % (self.args, self.username, self.password, self.service, self.target)
        return shlex.split(command)

    def host_check(self):
        for flag in self.flag_list:
            if flag in self.stderr:
                return {"target": self.target, "result": {'username': self.username, "password": self.password}}
        if "successfully" in self.stdout and self.target in self.stdout:
            return {"target": self.target, "result": {'username': self.username, "password": self.password}}
        elif 'can not connect' in self.stderr:
            return False
        elif 'waiting for children to finish' in self.stdout:
            return False
        else:
            return {"target": self.target, "result": ""}


if __name__ == "__main__":
    target_list = ['aquaman.org']
    service = 'ssh'
    username_list = ['root']
    password_list = ['123456']
    args = ''
    for _ in range(10):
        start = HydraScanner(target_list, service, username_list, password_list, args)
        result = start.run()
        # start._format_args()

        print result
        break
    """
    HydraScanner.run ['hydra', '-w', '15', '-C', '/tmp/hydra_dict_vH4GoWrA', '-M', '/tmp/hydra_target_ciwVH6BN', 'ssh']
    [{'username': 'root', 'password': '123456', 'target': '172.31.50.177', 'service': 'ssh'}]
    """
