# coding=utf-8
import os
basedir = os.path.abspath(os.path.dirname(__file__))

# 项目根目录
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Web APP
WEB_APP = BASE_DIR + '/aquaman'
# Web功能模块
MODULES = WEB_APP + '/modules'
# poc插件目录
POC_FILEPATH = MODULES + '/poc_vul/pocsuite_plugin/'
# TASK Schedule日志目录
TASK_SCHEDULE_LOG_DIR = BASE_DIR + '/logs/schedule/'
# 日志等级
LOG_LEVEL = 'INFO'

WEB_USER = 'admin'
WEB_PASSWORD = '123456'
WEB_HOST = '0.0.0.0'
WEB_PORT = 9777
VERSION = '1.1.0'
# AWVS_URL = 'https://127.0.0.1:13443'
AWVS_URL = 'https://172.31.50.177:23443'
# AWVS_API_KEY = '1986ad8c0a5b3df4d7028d5f3c06e936c8666d45bdb6546ab89bbeb27be42faae'
AWVS_API_KEY = '1986ad8c0a5b3df4d7028d5f3c06e936ce522c4fdd73647d8865c5decb79c41f9'
AWVS_REPORT_PATH = '/usr/local/nginx/static/aquaman/download/'

DB_HOST = '172.31.50.177'  # MongoDB Host
DB_PORT = 27017  # MongoDB Port (int)
DB_NAME = 'aquaman'
DB_USERNAME = 'aquaman'  # MongoDB User
DB_PASSWORD = '123456'  # MongoDB Password
CONFIG_NAME = 'aquaman'  # Scanner config name
PLUGIN_DB = 'dev_plugin_info'  # Plugin collection
TASKS_DB = 'dev_tasks'  # Scan tasks collection
CUS_DB = 'dev_customer'  # Scan tasks collection
VULNERABILITY_DB = 'dev_vuldb'  # Vulnerability collection
ASSET_DB = 'dev_asset'  # Asset collection
CONFIG_DB = 'dev_config'  # Scanner config collection
SERVER_DB = 'dev_server'  # Asset server collection
SUBDOMAIN_DB = 'dev_subdomain'  # Subdomain server collection
DOMAIN_DB = 'dev_domain'  # Domain server collection
PORT_DB = 'dev_port_scanner'  # Port scan collection
AUTH_DB = 'dev_auth_tester'  # Auth tester tasks collection
VULSCAN_DB = 'dev_vulscan'  # Acunetix scanner tasks collection
WEEKPASSWD_DB = 'dev_week_passwd'  # Week password collection

INSTANCE_DB = 'dev_instance'            # 实例记录
PORTINFO_DB = 'dev_port_info'           # 隶属实例的端口记录
VULWEB_DB = 'dev_vulweb_db'             # Web漏洞数据库 [-]
EXPLOIT_DB = 'dev_exploit_db'           # exploit与服务关联的数据库
DISCOVERY_DB = 'dev_discovery'          # 批量探测任务

SWAGGER_TITLE = 'Python Aquaman'
SWAGGER_DESC = '安全检测和安全监测服务 API'
SWAGGER_HOST = '172.31.50.177'
