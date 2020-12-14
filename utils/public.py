# -*- coding: utf-8 -*-
import ipaddr
import re
import hashlib


# 解析IP、IP段、URL, 并返回结果列表
def parse_target(host_list):
    result_list = []
    for host in host_list:
        host = host.strip()
        re_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')  # IP
        re_ips = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')  # IPs 一个IP段,172.31.50.254/24
        re_url = re.compile(r'[^\s]*.[a-zA-Z]')  # URL
        re_ip_port = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$')  # IP + Port
        re_url_port = re.compile(r'[^\s]*.[a-zA-Z]:\d{1,5}')  # URL + Port
        if re_ip.match(host):
            result_list.append(host)
        elif re_ips.match(host):
            hosts = ipaddr.IPv4Network(host).iterhosts()
            for ip in hosts:  # 172.31.50.254/24 ==> 172.31.50.[1-254]
                result_list.append(str(ip))
        elif re_url.match(host):
            result_list.append(host)
        elif re_ip_port.match(host):
            result_list.append(host)
        elif re_url_port.match(host):
            result_list.append(host)
        else:
            print("[!]", host, 'Target is not recognized as legal')
    return result_list


def port_service(port):
    port = "%s" % port
    data = {
        '21': {'service': 'ftp', 'desc': 'FTP文件传输协议', 'threat': '允许匿名的上传、下载、爆破和嗅探操作'},
        '22': {'service': 'ssh', 'desc': 'SSH远程连接', 'threat': '爆破、SSH隧道及内网代理转发、文件传输'},
        '23': {'service': 'telnet', 'desc': 'TELNET远程连接', 'threat': '爆破、嗅探、弱口令'},
        '25': {'service': 'smtp', 'desc': 'SMTP邮件服务', 'threat': '邮件伪造'},
        '53': {'service': 'dns', 'desc': 'DNS域名系统', 'threat': '允许区域传送、DNS劫持、缓存投毒、欺骗'},
        '67': {'service': 'dhcp', 'desc': 'DHCP服务', 'threat': '劫持、欺骗'},
        '68': {'service': 'dhcp', 'desc': 'DHCP服务', 'threat': '劫持、欺骗'},
        '69': {'service': 'tftp', 'desc': 'TFTP文件传输协议', 'threat': '允许匿名的上传、下载、爆破和嗅探操作'},
        '80': {'service': 'http', 'desc': '常用Web端口', 'threat': 'Web攻击、爆破、对应服务版本漏洞'},
        '110': {'service': 'pop3', 'desc': 'POP3协议', 'threat': '爆破、嗅探'},
        '143': {'service': 'imap', 'desc': 'IMAP协议', 'threat': '爆破'},
        '389': {'service': 'ldap', 'desc': 'LDAP目录访问协议', 'threat': '注入、允许匿名访问、弱口令'},
        '443': {'service': 'https', 'desc': '常用安全协议的Web端口', 'threat': 'Web攻击、爆破、对应服务版本漏洞'},
        '445': {'service': 'smb', 'desc': 'SAMBA', 'threat': '爆破、未授权访问、远程执行'},
        '1433': {'service': 'mmsql', 'desc': 'MMSQL', 'threat': '注入、提权、SA弱口令、爆破'},
        '1521': {'service': 'oracle', 'desc': 'Oracle', 'threat': 'TNS爆破、注入、反弹Shell'},
        '2181': {'service': 'zookeeper', 'desc': 'Zookeeper服务', 'threat': '未授权访问'},
        '3306': {'service': 'mysql', 'desc': 'Mysql数据库服务', 'threat': '注入、提权、爆破'},
        '3389': {'service': 'rdp', 'desc': 'RDP远程桌面连接', 'threat': 'Shift后门(需要Windowns Server 2003以下的系统)、爆破'},
        '3690': {'service': 'svn', 'desc': 'SVN服务', 'threat': 'SVN泄露、未授权访问'},
        '5900': {'service': 'vnc', 'desc': 'VNC', 'threat': '弱口令爆破'},
        '5901': {'service': 'vnc', 'desc': 'VNC', 'threat': '弱口令爆破'},
        '5902': {'service': 'vnc', 'desc': 'VNC', 'threat': '弱口令爆破'},
        '5903': {'service': 'vnc', 'desc': 'VNC', 'threat': '弱口令爆破'},
        '6379': {'service': 'redis', 'desc': 'Redis数据库服务', 'threat': '未授权访问、弱口令爆破'},
        '7001': {'service': 'weblogic', 'desc': 'WebLogic控制台', 'threat': 'Java反序列化、弱口令'},
        '7002': {'service': 'weblogic', 'desc': 'WebLogic控制台', 'threat': 'Java反序列化、弱口令'},
        '8080': {'service': 'http', 'desc': '常用Web端口', 'threat': 'Web攻击、爆破、对应服务版本漏洞'},
        '9200': {'service': 'elasticsearch', 'desc': 'Elasticsearch服务', 'threat': '远程执行'},
        '9300': {'service': 'elasticsearch', 'desc': 'Elasticsearch服务', 'threat': '远程执行'},
        '11211': {'service': 'memcache', 'desc': 'Memcache服务', 'threat': '未授权访问'},
        '27017': {'service': 'mongo', 'desc': 'MongoDB', 'threat': '未授权访问'},
    }
    if port in data.keys():
        return data[port]
    return False


def http_server(server):
    # JSP3/2.0.14
    # Apache
    # nginx
    server = server.strip().lower()
    srv = re.split(r'[\s/]', server)
    server = srv[0]
    version = ''
    if len(srv) > 1:
        version = srv[1]
    if 'jsp' in server:
        return {'product': server, 'version': version}
    if 'tomcat' in server:
        return {'product': server, 'version': version}
    if 'nginx' in server:
        return {'product': server, 'version': version}
    if 'apache' in server:
        return {'product': server, 'version': version}
    return False


def md5hash(ip):
    md5 = hashlib.md5()
    md5.update(ip)
    return md5.hexdigest()
