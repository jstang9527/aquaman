# coding=utf-8
# desc: ip地址识别
# return {'gps': '', 'isp': u'\u5bf9\u65b9\u548c\u60a8\u5728\u540c\u4e00\u5185\u90e8\u7f51', 'area': u'\u5c40\u57df\u7f51'}
from qqwry import QQwry
import random
import requests
from bs4 import BeautifulSoup as BS
import time
import json


def requests_headers():
    '''
    Random UA  for every requests && Use cookie to scan
    '''
    user_agent = [
        'Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0',
        'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.6 Safari/532.0',
        'Mozilla/5.0 (Windows; U; Windows NT 5.1 ; x64; en-US; rv:1.9.1b2pre) Gecko/20081026 Firefox/3.1b2pre',
        'Opera/10.60 (Windows NT 5.1; U; zh-cn) Presto/2.6.30 Version/10.60', 'Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4062; en; U; ssr)',
        'Mozilla/5.0 (Windows; U; Windows NT 5.1; ; rv:1.9.0.14) Gecko/2009082707 Firefox/3.0.14',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
        'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr; rv:1.9.2.4) Gecko/20100523 Firefox/3.6.4 ( .NET CLR 3.5.30729)',
        'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
        'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5'
    ]
    UA = random.choice(user_agent)
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'User-Agent': UA, 'Upgrade-Insecure-Requests': '1', 'Connection': 'keep-alive', 'Cache-Control': 'max-age=0',
        'Accept-Encoding': 'gzip, deflate, sdch', 'Accept-Language': 'zh-CN,zh;q=0.8',
        "Referer": "http://www.baidu.com/link?url=www.so.com&url=www.soso.com&&url=www.sogou.com",
        'Cookie': "PHPSESSID=gljsd5c3ei5n813roo4878q203"
    }
    return headers


def getip_info_taobao(ip):
    try:
        url = "http://ip.taobao.com/service/getIpInfo.php?ip=" + ip
        print url
        res = requests.get(url, headers=requests_headers(), timeout=10)
        res = json.loads(res.content)
        print res
        if res['code'] == 0:
            country = res['data']['country']
            region = res['data']['region']
            city = res['data']['city']
            isp = res['data']['isp']
        else:
            country = None
            region = None
            city = None
            isp = None
        if region or city:
            area = region + city
        else:
            area = country
        return area, isp
    except Exception:
        return '', ''


def getipgps(ip):
    try:
        url1 = 'http://ip-api.com/json/' + str(ip)
        print url1
        res1 = requests.get(url1, headers=requests_headers(), timeout=15, verify=False)
        info = eval(res1.content)
        gps = str(info['lat']) + ',' + str(info['lon'])

        if gps:
            # print gps[0]
            return gps
        else:
            url = 'http://www.gpsspg.com/ip/?q=' + ip
            # http://ip-api.com/json/112.231.42.101
            print url
            res = requests.get(url, headers=requests_headers(), timeout=15)
            html = res.content
            soup = BS(html, 'lxml')
            td = soup.find_all('a')
            gps = td[7].text
            if gps.startswith('http'):
                return '0,0'
            else:
                return gps
    except Exception:
        return ''


def getip_info_gpsspg(ip):
    try:
        url = 'http://www.gpsspg.com/ip/?q=' + ip
        print url
        res = requests.get(url, timeout=30)
        html = res.content
        # print html
        soup = BS(html, 'lxml')
        td = soup.find_all('span')
        area = td[3].text
        country = None
        region = None
        city = None
        isp = None
        isp = area.split('--')[1].strip()
        country = area.split('--')[0].split(' ')[0]
        region = area.split('--')[0].split(' ')[1]
        city = area.split('--')[0].split(' ')[2]
        if region or city:
            area = region + city
        else:
            area = country
        return area, isp
    except Exception:
        return '', ''


def getip_info_local(ip):
    try:
        q = QQwry()
        q.load_file('./qqwry.dat')
        result = q.lookup(ip)
        area = result[0]
        isp = result[1]
        return area, isp, True
    except Exception:
        return '', '', False


def getipinfo(ip):
    if not ip:
        return False
    try:
        area, isp, flag = getip_info_local(ip)
        # print "getip_info_local_ok",time.strftime('%Y-%m-%d %X', time.localtime(time.time()))
        if not flag:
            area, isp, flag = getip_info_gpsspg(ip)
            print "getip_info_gpsspg_ok", time.strftime('%Y-%m-%d %X', time.localtime(time.time()))
            if not flag:
                area, isp, flag = getip_info_taobao(ip)
                print "getip_info_taobao_ok", time.strftime('%Y-%m-%d %X', time.localtime(time.time()))

        gps = getipgps(ip)
        # print "getipgps_Ok:",time.strftime('%Y-%m-%d %X', time.localtime(time.time()))
        ipinfo = {'area': area, 'isp': isp, 'gps': gps}
        return ipinfo
    except Exception:
        return False


if __name__ == "__main__":
    data = getipinfo('192.168.231.119')
    print '[+] data: ', data
