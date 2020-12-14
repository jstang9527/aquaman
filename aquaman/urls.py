# coding=utf-8
from aquaman.views.ping_pong import TestAPI
from aquaman.views.auth_tester import AuthTesterConfigView, AuthTesterTaskView, AuthTesterTasksView, AuthTesterDetectView
from aquaman.views.authenticate import AuthenticateView, AuthenticatedView
from aquaman.views.web_vul import WebVulTaskView, WebVulTasksView, WebVulDetectList, WebVulDetect
from aquaman.views.poc_vul import PocVulDetectView, PocVulTaskView, PocVulTasksView, PocPluginView, PocCodeView
from aquaman.views.msf_exploit import ExploitInfoView, ExploitInfoListView, ExploitListView
from aquaman.views.asset_mgr import AssetInfoView, AssetInfoListView
from aquaman.views.dashboard import TopCard
from aquaman.views.sys_config import SysConfig
from aquaman.views.instance_mgr import InstanceInfoView, InstanceInfoListView, ServiceList, AssetTaskList, AssetTask
# from aquaman.views.service import ServiceInfoListView, ServiceInfoView

test_view = TestAPI.as_view('test')
authenticate = AuthenticateView.as_view('authenticate')
authenticated = AuthenticatedView.as_view('authenticated')
auth_tester_config = AuthTesterConfigView.as_view('auth_tester_config')
auth_tester_task = AuthTesterTaskView.as_view('auth_tester_task')
auth_tester_tasks = AuthTesterTasksView.as_view('auth_tester_tasks')
auth_tester_detect = AuthTesterDetectView.as_view('auth_tester_detect')

webvul_task = WebVulTaskView.as_view('webvul_task')
webvul_tasks = WebVulTasksView.as_view('webvul_tasks')
webvul_detect = WebVulDetect.as_view('webvul_detect')
webvul_detect_list = WebVulDetectList.as_view('webvul_detect_list')

pocvul_task = PocVulTaskView.as_view('pocvul_task')
pocvul_tasks = PocVulTasksView.as_view('pocvul_tasks')
pocvul_detect = PocVulDetectView.as_view('pocvul_detect')
poc_plugin = PocPluginView.as_view('poc_plugin')
exploit_info = ExploitInfoView.as_view('exploit_info')
exploit_info_list = ExploitInfoListView.as_view('exploit_info_list')
exploit_mname = ExploitListView.as_view('exploit_mname')
poc_code = PocCodeView.as_view('poc_code')

assetinfo = AssetInfoView.as_view('assetinfo')
assetinfo_list = AssetInfoListView.as_view('assetinfo_list')

instance_info = InstanceInfoView.as_view('instance_info')
instance_list = InstanceInfoListView.as_view('instance_list')
service_list = ServiceList.as_view('service_list')
asset_task = AssetTask.as_view('asset_task')
asset_task_list = AssetTaskList.as_view('asset_task_list')

topcard = TopCard.as_view('topcard')
sysconfig = SysConfig.as_view('sysconfig')


def register_api(app):
    app.add_url_rule('/test', view_func=test_view, methods=['GET', 'POST'])
    # 管理员接口
    app.add_url_rule('/admin/login', view_func=authenticate, methods=['POST'])
    app.add_url_rule('/admin', view_func=authenticated, methods=['GET', 'POST'])
    # 弱口令认证
    app.add_url_rule('/auth_tester/config', view_func=auth_tester_config, methods=['GET'])
    app.add_url_rule('/auth_tester/task', view_func=auth_tester_task, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    app.add_url_rule('/auth_tester/tasks', view_func=auth_tester_tasks, methods=['GET'])
    app.add_url_rule('/auth_tester/detect', view_func=auth_tester_detect, methods=['GET', 'DELETE'])
    # Web漏洞检测
    app.add_url_rule('/webvul/tasks', view_func=webvul_tasks, methods=['GET'])
    app.add_url_rule('/webvul/task', view_func=webvul_task, methods=['GET', 'POST', 'DELETE'])
    app.add_url_rule('/webvul/detect/list', view_func=webvul_detect_list, methods=['GET'])
    app.add_url_rule('/webvul/detect', view_func=webvul_detect, methods=['GET', 'DELETE', 'PATCH'])

    # Poc漏洞检测
    app.add_url_rule('/pocvul/tasks', view_func=pocvul_tasks, methods=['GET'])
    app.add_url_rule('/pocvul/task', view_func=pocvul_task, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    app.add_url_rule('/pocvul/detect', view_func=pocvul_detect, methods=['GET', 'DELETE'])
    app.add_url_rule('/pocvul/plugin', view_func=poc_plugin, methods=['GET', 'POST', 'DELETE'])
    app.add_url_rule('/pocvul/exploit/list', view_func=exploit_info_list, methods=['GET'])
    app.add_url_rule('/pocvul/exploit/info', view_func=exploit_info, methods=['GET', 'POST', 'PUT', 'DELETE'])
    app.add_url_rule('/pocvul/exploit/mname', view_func=exploit_mname, methods=['GET'])  # 远程查询 [-]
    app.add_url_rule('/pocvul/plugin/detail', view_func=poc_code, methods=['GET'])

    # 资产管理
    app.add_url_rule('/asset/info', view_func=assetinfo, methods=['GET', 'POST', 'DELETE'])
    app.add_url_rule('/asset/list', view_func=assetinfo_list, methods=['GET'])

    # 实例管理
    app.add_url_rule('/instance/info', view_func=instance_info, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    app.add_url_rule('/instance/list', view_func=instance_list, methods=['GET'])
    app.add_url_rule('/instance/service/list', view_func=service_list, methods=['GET'])
    app.add_url_rule('/instance/discovery/list', view_func=asset_task_list, methods=['GET'])
    app.add_url_rule('/instance/discovery', view_func=asset_task, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])

    # 端口服务发现
    # app.add_url_rule('/service/list', view_func=service_list, methods=['GET'])
    # app.add_url_rule('/service/info', view_func=service_info, methods=['GET'])

    # 首页大盘
    app.add_url_rule('/dashboard', view_func=topcard, methods=['GET'])

    # 系统设置
    app.add_url_rule('/sys/config', view_func=sysconfig, methods=['GET', 'PUT'])

    return app
