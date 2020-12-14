# coding=utf-8
# desc: 更多调用方法详看API文档

import requests
import os
import sys
import json
import nmap
import time
import hashlib


def md5hash(ip):
    md5 = hashlib.md5()
    md5.update(ip)
    return md5.hexdigest()


def nmap_ping_scan(network_prefix):
    nm = nmap.PortScanner()     # 设置为nmap扫描状态。
    ping_scan_raw = nm.scan(hosts=network_prefix, arguments='-sn')   # hosts可以是单个IP地址也可以是一整个网段。    arguments就是运用什么方式扫描，-sn就是ping扫描。
    host_list_ip = []
    for result in ping_scan_raw['scan'].values():  # 将scan下面的数值赋值给result，并开始遍历。
        if result['status']['state'] == 'up':  # 如果是up则表明对方主机是存活的。
            host_list_ip.append(result['addresses']['ipv4'])   # 在addresses层下的ipv4，也就是IP地址添加到result字典中。
    return host_list_ip   # 返回字典。


def help():
    print "python python.py help"
    print "[Usage]:\n\t python python.py (function) (method) [flag]"
    print "\n[Method]: \n\tGET|POST"
    print "\n[Flag]: \n\tid|data|Null"
    print """\n[Function]:
    \t\t\t批量探测(会自动生成多个资产任务) \rauto_task
    \t\t\t资产任务 \rasset_task
    \t\t\t资产详情(包含各种检出) \rasset_info
    \t\t\tPoc检测任务 \rpoc_task
    \t\t\tWeb检测任务 \rweb_task
    \t\t\t认证爆破任务 \rauth_task
    \t\t\tPoc检测结果 \rpoc_detect
    \t\t\tweb检测结果 \rweb_detect
    \t\t\tauth检测结果 \rauth_detect
    \t\t\t系统配置信息 \rsys_config"""
    print "\n[Exapmle]:"
    print '\t\t\tpython python.py auto_task post \'{"ip":"172.31.50.0/24"}\' \r发布网络段资产探测任务'
    print '\t\t\tpython python.py asset_task post \'{"name":"test","target":"IP/Domain","port_mode":0,"recursion":0,"open_web":0,"open_poc":0,"open_auth":0}\' \r发布指定IP资产探测任务'
    print "\t\t\tpython python.py auth_task get \r获取所有认证爆破任务"
    print "\t\t\tpython python.py auth_task get 5f9fabdd695288f46e631edb \r获取单个认证爆破任务"
    print "\n[More Help] http://172.31.50.177:9777/swagger"


# IP网络段自动探测任务
def autumation(range):
    # target_val = '172.31.50.0/24'  # 172.31.50.0/24
    # new_scan = NmapScanner(target_val, "", "-sP")  # ping扫描
    # print new_scan.run()
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts="172.31.50.0/24", ports="21,22", arguments="-sP")
    except Exception as e:
        print e
    ips = nm.all_hosts()
    print ips


class Scanner:
    def __init__(self, args):
        self.API_SERVER = 'http://172.31.50.177:9777/'
        self.args = args

    def get_all_asset(self):
        url = self.API_SERVER + 'instance/list'
        params = {'page_size': 10, 'page_no': 1}
        resp = requests.get(url, params=params)
        print resp.content

    # get方法
    def get_method(self, fun=None, id=None):
        if 'asset_task' in fun:
            if id:
                url = self.API_SERVER + 'instance/info'
                params = {'instance_id': id, 'simple': 1}
                resp = requests.get(url, params=params)
            else:
                url = self.API_SERVER + 'instance/list'
                resp = requests.get(url)
            print resp.content
        elif 'auth_task' in fun:
            if id:
                url = self.API_SERVER + 'auth_tester/task'
                params = {"task_id": id}
                resp = requests.get(url, params=params)
            else:
                url = self.API_SERVER + 'auth_tester/tasks'
                resp = requests.get(url)
            print resp.content
        elif 'poc_task' in fun:
            if id:
                url = self.API_SERVER + 'pocvul/task'
                params = {"task_id": id}
                resp = requests.get(url=url, params=params)
            else:
                url = self.API_SERVER + 'pocvul/tasks'
                resp = requests.get(url)
            print resp.content
        elif 'web_task' in fun:
            if id:
                url = self.API_SERVER + '/webvul/task'
                parmas = {"task_id": id}
                resp = requests.get(url, params=parmas)
            else:
                url = self.API_SERVER + 'webvul/tasks'
                resp = requests.get(url)
            print resp.content
        elif 'auth_detect' in fun:
            # 根据任务ID查对应记录
            if id:
                res = requests.get(url=self.API_SERVER + 'auth_tester/task', params={"task_id": id})
                if res.status_code == 500:
                    print("不存在该任务ID({})".format(id))
                    return
                try:
                    info = json.loads(res.content)['data']['task_name']
                except Exception:
                    print "该任务ID({})下没有任何检出记录，即为安全.".format(id)
                    return
                resp = requests.get(url=self.API_SERVER + 'auth_tester/detect', params={'info': info})
            # 否则查所有
            else:
                url = self.API_SERVER + 'auth_tester/detect'
                resp = requests.get(url)
            print resp.content
        elif 'poc_detect' in fun:
            if id:
                # 根据任务ID查检出结果
                res = requests.get(self.API_SERVER + 'pocvul/task', params={"task_id": id})
                if res.status_code == 500:
                    print("不存在该任务ID({})".format(id))
                    return
                try:
                    info = json.loads(res.content)['data']['task_name']
                except Exception:
                    print "该任务ID({})下没有任何检出记录，即为安全.".format(id)
                    return
                resp = requests.get(url=self.API_SERVER + 'pocvul/detect', params={'info': info})
            else:
                resp = requests.get(url=self.API_SERVER + 'pocvul/detect')
            print resp.content
        elif 'web_detect' in fun:
            if id:
                # 根据任务ID查检出结果
                resp = requests.get(url=self.API_SERVER + '/webvul/detect/list', params={'info': id})
            else:
                resp = requests.get(url=self.API_SERVER + '/webvul/detect/list')
            print resp.content
        elif 'poc_plugin' in fun:
            resp = requests.get(url=self.API_SERVER + 'pocvul/plugin')
            print resp.content
        elif 'asset_info' in fun:
            if id:
                url = self.API_SERVER + 'instance/info'
                params = {'instance_id': id}
                resp = requests.get(url, params=params)
            else:
                url = self.API_SERVER + 'instance/list'
                resp = requests.get(url)
            print resp.content
        elif 'sys_config' in fun:
            resp = requests.get(url=self.API_SERVER + 'sys/config')
            print resp.content
        else:
            print "不存在该功能!"
            print "[warning] please execute command 'python python.py help'"

    # post方法
    def post_method(self, fun=None, data=None):
        if 'asset_task' in fun:
            resp = requests.post(url=self.API_SERVER + 'instance/info', data=data)
            print resp.content
            try:
                instance_id = json.loads(resp.content)['data']['instance_id']
                requests.patch(url=self.API_SERVER + 'instance/info', params={"id": instance_id})
            except Exception:
                return
        elif 'auth_task' in fun:
            resp = requests.post(url=self.API_SERVER + 'auth_tester/task', data=data)
            print resp.content
        elif 'poc_task' in fun:
            resp = requests.post(url=self.API_SERVER + 'pocvul/task', data=data)
            print resp.content
        elif 'web_task' in fun:
            resp = requests.post(url=self.API_SERVER + 'webvul/task', data=data)
            print resp.content
        elif 'auto_task':
            ips = data['ip']
            print "正在探测主机存活并生成资产任务..."
            for host in nmap_ping_scan(ips):  # 输入你要扫描的网段。
                params = {
                    "name": host.split('.')[-1] + '_' + md5hash(host)[:3] + time.strftime("%M%S", time.localtime()),
                    "target": host, "port_mode": 0, "recursion": 0, "port_list": [],
                    "open_web": 0, "open_poc": 0, "open_auth": 0
                }
                resp = requests.post(url=self.API_SERVER + 'instance/info', data=json.dumps(params))
                iid = json.loads(resp.content)['data']['instance_id']
                time.sleep(0.5)
                requests.patch(self.API_SERVER + 'instance/info', params={"id": iid})
            print "完成探测主机存活并生成资产任务..."
        else:
            print "[error]: one of functions [asset_task, auth_task, poc_task, web_task, auto_task]"

    def run(self):
        id = None
        if len(self.args) == 4:
            id = self.args[3]
        if len(self.args) < 1:
            print "[warning] please execute command 'python python.py help'"
            return

        if 'help' in self.args[1]:
            help()
            return

        if len(self.args) < 3:
            print "[warning] please execute command 'python python.py help'"
            return

        if 'get' in self.args[2]:
            self.get_method(fun=self.args[1], id=id)
        elif 'post' in self.args[2]:
            try:
                data = json.loads(self.args[3])
                self.post_method(fun=self.args[1], data=data)
            except Exception as e:
                print "data参数类型错误,请看帮助python python.py help", e

    def clear(self):
        os.system('cls')


if __name__ == "__main__":
    # scanner = Scanner(sys.argv)
    # scanner.run()
    # host = '172.31.50.177'
    # params = {
    #     "name": host.split('.')[-1] + '_' + md5hash(host)[:3] + time.strftime("%M%S", time.localtime()),
    #     "target": host, "port_mode": 0, "recursion": 0, "port_list": [],
    #     "open_web": 0, "open_poc": 0, "open_auth": 0
    # }
    # requests.post(url='http://172.31.50.177:9777/instance/info', data=json.dumps(params))
    print nmap_ping_scan('172.31.50.252,172.31.50.254')
