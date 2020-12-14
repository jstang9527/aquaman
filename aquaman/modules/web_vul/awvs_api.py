# -*- coding: utf-8 -*-
# desc:  systemctl stop acunetix_trial.service
import os
import time
import json
import requests
from application import settings

requests.packages.urllib3.disable_warnings()


class AcunetixScanner:
    def __init__(self):
        self.api_key = settings.AWVS_API_KEY
        self.scanner_url = settings.AWVS_URL
        self.awvs_report_path = settings.AWVS_REPORT_PATH
        self.scan_result = {}
        self.all_tasks = []
        self.report_url = []
        self.headers = {
            "X-Auth": self.api_key,
            "content-type": "application/json"
        }

    def new_scan(self, target, desc):
        data = {"address": target, "description": desc, "criticality": "10"}
        try:
            response = requests.post(self.scanner_url + "/api/v1/targets", data=json.dumps(data),
                                     headers=self.headers, timeout=30, verify=False)
            return json.loads(response.content)['target_id']
        except Exception as e:
            print(target, e)
            return False

    def start_task(self, target, desc, profile_id):
        profile_id_list = {'0': '11111111-1111-1111-1111-111111111111', '1': '11111111-1111-1111-1111-111111111112',
                           '2': '11111111-1111-1111-1111-111111111116', '3': '11111111-1111-1111-1111-111111111113',
                           '4': '11111111-1111-1111-1111-111111111115', '5': '11111111-1111-1111-1111-111111111117'}
        profile_id = profile_id_list[profile_id]
        target_id = self.new_scan(target, desc)
        if not target_id:
            return False
        data = {
            "target_id": target_id,
            "profile_id": profile_id,
            "schedule": {
                "disable": False,
                "start_date": None,
                "time_sensitive": False
            }
        }
        try:
            response = requests.post(self.scanner_url + "/api/v1/scans", data=json.dumps(data),
                                     headers=self.headers, timeout=30, verify=False)
            return json.loads(response.content)
        except Exception as e:
            print(target, target_id, e)
            return False

    # 获取所有扫描记录
    def get_all(self):
        try:
            response = requests.get(self.scanner_url + "/api/v1/scans", headers=self.headers, timeout=30, verify=False)
            results = json.loads(response.content)
            task_info = {}
            for task in results['scans']:
                task_info['scan_id'] = task['scan_id']
                task_info['target_id'] = task['target_id']
                task_info['address'] = task['target']['address']
                task_info['desc'] = task['target']['description']
                task_info['profile_name'] = task['profile_name']
                if 'current_session' not in task.keys():
                    task_info['vul_high'] = 0
                    task_info['vul_medium'] = 0
                    task_info['vul_low'] = 0
                    task_info['vul_info'] = 0
                    task_info['start_date'] = ""
                    task_info['status'] = "processing"
                    task_info['scan_session_id'] = ""
                else:
                    task_info['vul_high'] = task['current_session']['severity_counts']['high']
                    task_info['vul_medium'] = task['current_session']['severity_counts']['medium']
                    task_info['vul_low'] = task['current_session']['severity_counts']['low']
                    task_info['vul_info'] = task['current_session']['severity_counts']['info']
                    task_info['start_date'] = task['current_session']['start_date'][0:19].replace('T', ' ')
                    task_info['status'] = task['current_session']['status']
                    task_info['scan_session_id'] = task['current_session']['scan_session_id']
                self.all_tasks.append(task_info)
                task_info = {}
            return self.all_tasks
        except Exception as e:
            raise e

    # 根据scan_id获取扫描记录详情
    def get_scaninfo(self, scan_id):
        try:
            url = self.scanner_url + "/api/v1/scans/" + str(scan_id)
            response = requests.get(url, headers=self.headers, timeout=30, verify=False)
            data = json.loads(response.content)
            result = {}
            result['scan_id'] = data['scan_id']
            result['target_id'] = data['target_id']
            result['address'] = data['target']['address']
            result['desc'] = data['target']['description']
            result['profile_name'] = data['profile_name']
            if 'current_session' not in data.keys():
                result['vul_high'] = 0
                result['vul_medium'] = 0
                result['vul_low'] = 0
                result['vul_info'] = 0
                result['start_date'] = ""
                result['status'] = "processing"
                result['scan_session_id'] = ""
            else:
                result['vul_high'] = data['current_session']['severity_counts']['high']
                result['vul_medium'] = data['current_session']['severity_counts']['medium']
                result['vul_low'] = data['current_session']['severity_counts']['low']
                result['vul_info'] = data['current_session']['severity_counts']['info']
                result['start_date'] = data['current_session']['start_date'][0:19].replace('T', ' ')
                result['status'] = data['current_session']['status']
                result['scan_session_id'] = data['current_session']['scan_session_id']
            return result

        except Exception as e:
            print scan_id, e
            return False

    # 删除扫描记录
    def delete_scan(self, scan_id):
        try:
            url = self.scanner_url + "/api/v1/scans/" + str(scan_id)
            response = requests.delete(url, headers=self.headers, timeout=30, verify=False)
            if response.status_code == 204:
                return True
            else:
                return False
        except Exception as e:
            print(scan_id, e)
            return False

    def delete_target(self, target_id):
        try:
            response = requests.delete(self.scanner_url + "/api/v1/targets/" + str(target_id),
                                       headers=self.headers, timeout=30, verify=False)
            if response.status_code == 204:
                return True
            else:
                return False
        except Exception as e:
            print(target_id, e)
            return False

    def reports(self, id_list, list_type, task_name):
        # list_type = "scans", 'targets' ...
        data = {
            "template_id": "11111111-1111-1111-1111-111111111115",
            "source": {
                "list_type": list_type,
                "id_list": id_list
            }
        }
        try:
            response = requests.post(self.scanner_url + "/api/v1/reports", headers=self.headers,
                                     data=json.dumps(data), timeout=30, verify=False)
            if response.status_code == 201:
                while True:
                    res_down = requests.get(self.scanner_url + response.headers['Location'],
                                            headers=self.headers, timeout=30, verify=False)
                    if json.loads(res_down.content)['status'] == "completed":
                        for report_url in json.loads(res_down.content)['download']:
                            report_res = requests.get(self.scanner_url + report_url, timeout=30, verify=False)
                            report_name = time.strftime("%y%m%d", time.localtime()) + "_" + task_name[0] + '.' + report_url.split('.')[-1]
                            if os.path.exists(self.awvs_report_path + report_name):
                                os.remove(self.awvs_report_path + report_name)
                            with open(self.awvs_report_path + report_name, "wb") as report_content:
                                report_content.write(report_res.content)
                            self.report_url.append(report_name)
                        return self.report_url
            else:
                return False
        except Exception as e:
            print(id_list, e)
            return False

    def get_scaninfo_old(self, scan_id):  # Scan Status & info
        _ = {
            "next_run": 'null',
            "scan_id": "d4d82b6b-9a1d-4908-b0b0-54cf426ce14a",
            "manual_intervention": 'false',
            "criticality": 10,
            "schedule": {
                "recurrence": 'null',
                "history_limit": 'null',
                "disable": 'false',
                "time_sensitive": 'false',
                "start_date": 'null'
            },
            "current_session": {
                "status": "completed",
                "event_level": 0,
                "start_date": "2020-10-15T08:16:32.305728+00:00",
                "threat": 3,
                "progress": 0,
                "severity_counts": {
                    "high": 1,
                    "info": 15,
                    "medium": 40,
                    "low": 20
                },
                "scan_session_id": "3cb9659e-8ede-4964-bcf8-35ac4ed978a2"
            },
            "profile_id": "11111111-1111-1111-1111-111111111111",
            "target_id": "a8bbeb63-a6f3-467a-b176-af1893b5c4f5",
            "profile_name": "Full Scan",
            "report_template_id": 'null',
            "target": {
                "type": "default",
                "description": "",
                "criticality": 10,
                "address": "http://172.31.50.254"
            }
        }
        try:
            url = self.scanner_url + "/api/v1/scans/" + str(scan_id)
            response = requests.get(url, headers=self.headers, timeout=30, verify=False)
            return json.loads(response.content)

        except Exception as e:
            print scan_id, e
            return False

    def get_vullist(self, scan_id, scan_session_id):
        """
        [-] return array
        [*] 需要扫描一段时间才会出来scan_session_id
        """
        _ = {
            "vulnerabilities": [
                {
                    "affects_detail": "",
                    "affects_url": "http://172.31.50.254/",
                    "criticality": 10,
                    "last_seen": "null",
                    "loc_id": 2,
                    "severity": 3,
                    "status": "open",
                    "tags": [
                        "CWE-16",
                        "configuration",
                        "information_disclosure"
                    ],
                    "target_id":"a8bbeb63-a6f3-467a-b176-af1893b5c4f5",
                    "vt_id":"2d93d32d-b2ee-62c9-12cb-3d9b67d247a3",
                    "vt_name":"Elasticsearch service accessible",
                    "vuln_id":"2420363122557584890"
                },
                {
                    "affects_detail": "lang",
                    "affects_url": "http://172.31.50.254/index.php",
                    "criticality": 10,
                    "last_seen": "null",
                    "loc_id": 467,
                    "severity": 2,
                    "status": "open",
                    "tags": [
                        "CWE-200",
                        "information_disclosure",
                        "error_handling"
                    ],
                    "target_id":"a8bbeb63-a6f3-467a-b176-af1893b5c4f5",
                    "vt_id":"760d5a01-dc58-fcbe-6c21-4f04c64a2467",
                    "vt_name":"Application error message",
                    "vuln_id":"2420363220947568162"
                }
            ],
            "pagination": {
                "next_cursor": "null",
                "previous_cursor": 0
            }
        }
        # https://172.31.50.177:13443/api/v1/scans/d4d82b6b-9a1d-4908-b0b0-54cf426ce14a/results/3cb9659e-8ede-4964-bcf8-35ac4ed978a2/vulnerabilities?q=status:open
        try:
            url = self.scanner_url + "/api/v1/scans/" + str(scan_id) + '/results/' + str(scan_session_id) + '/vulnerabilities'
            params = {'q': 'status:open'}
            response = requests.get(url, headers=self.headers, params=params, timeout=30, verify=False)
            return json.loads(response.content)

        except Exception as e:
            print scan_id, e
            return False

    # 获取该vul的详情，比如攻击方法、攻击结果
    def get_vuldetail(self, scan_id, scan_session_id, vuln_id):
        # https://172.31.50.177:13443/api/v1/scans/[scan_id]/results/[scan_session_id]/vulnerabilities/[vul_id] 就可以查到AWVS的攻击详情和攻击结果
        try:
            url = self.scanner_url + "/api/v1/scans/" + str(scan_id) + '/results/' + str(scan_session_id) + '/vulnerabilities/' + str(vuln_id)
            response = requests.get(url, headers=self.headers, timeout=30, verify=False)
            return json.loads(response.content)
        except Exception as e:
            print scan_id, e
            return False
