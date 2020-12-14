# coding=utf-8
# desc: 获取IP/域名的Web指纹
import requests
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class WebParser:
    def __init__(self, ip, port, scheme):
        self.ip = ip  # domain
        self.port = int(port)
        self.scheme = scheme
        self.headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36'
        }

    def fingerprints(self):
        result = {}
        url = '{}://{}:{}'.format(self.scheme, self.ip, self.port)
        if self.port == 80:
            url = '{}://{}'.format(self.scheme, self.ip)

        try:
            resp = requests.get(url, headers=self.headers, verify=False, timeout=1)
            match = re.search('<title>(.*?)</title>', resp.content)
            if match:
                title = match.group(1).decode('utf-8')
            else:
                title = 'None'
            for k, v in resp.headers.items():
                result[k] = v
            if 'server' not in result:
                result['server'] = 'Unkown'
            result['title'] = title
            result['status_code'] = resp.status_code
            result['content'] = resp.content
        except Exception:
            return False

        return result


if __name__ == "__main__":
    wp = WebParser('172.31.50.252', 445, 'http')
    print wp.fingerprints()
