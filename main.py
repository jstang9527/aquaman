# -*- coding: utf-8 -*-
import threading
# from flask import Flask
from application import settings
from gevent.pywsgi import WSGIServer
from aquaman.app import app
from aquaman.modules.auth_vul.auth_scanner import AuthTesterLoop
from aquaman.modules.poc_vul.poc_scanner import PocScannerLoop
from aquaman.modules.automation.asset_scanner import AssetScannerLoop
from aquaman.modules.web_vul.awvs_scanner import AwvsTaskLoop
# from aquaman.lib.mongo_db import init_db
thread_pool = []


def web_server(host, port):
    http_server = WSGIServer((host, port), app)
    http_server.serve_forever()


def auth_server():
    print("[*] Running Auth Schedule Task.")
    auth_task = AuthTesterLoop()
    auth_task.task_schedule()


def poc_server():
    print("[*] Running Poc Schedule Task.")
    poc_task = PocScannerLoop()
    poc_task.task_schedule()


def vul_server():
    print("[*] Running Vulns Schedule Task.")
    webvul_task = AwvsTaskLoop()
    webvul_task.task_schedule()


def asset_server():
    print("[*] Running Asset Schedule Task.")
    asset_task = AssetScannerLoop()
    asset_task.task_schedule()


if __name__ == "__main__":
    host = settings.WEB_HOST
    port = settings.WEB_PORT
    # print("[*] Init mongo cli mongo://" + settings.DB_HOST + ":" + str(settings.DB_PORT))
    # if not init_db():
    #     print("[-] Failed Connect MongoDB...")
    #     exit()
    print("[*] Running on http://" + host + ":" + str(port))
    thread_pool.append(threading.Thread(target=web_server, args=(host, port)))
    thread_pool.append(threading.Thread(target=auth_server, args=()))
    thread_pool.append(threading.Thread(target=poc_server, args=()))
    thread_pool.append(threading.Thread(target=vul_server, args=()))
    thread_pool.append(threading.Thread(target=asset_server, args=()))
    try:
        for t in thread_pool:
            t.start()
        for t in thread_pool:
            t.join()
    except Exception as e:
        print e
