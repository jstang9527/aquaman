#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : TideSec
# @Time    : 18-5-14
# @File    : parse_plugin.py
# @Desc    : ""

import sys
import os
import re
from flask import Flask
sys.path.append('/home/aquaman/')
from aquaman.lib.mongo_db import connectiondb, db_name_conf


app = Flask(__name__)
plugin_db = db_name_conf()['plugin_db']


def parse_plugin(plugin_filename):
    plugin_info = {}
    name_pattern = re.compile(r'\s*name\s*=\s*[\'\"\[](.*)[\'\"\]]')
    author_pattern = re.compile(r'author\s*=\s*[\'\"\[](.*)[\'\"\]]')
    date_pattern = re.compile(r'vulDate\s*=\s*[\'\"\[](.*)[\'\"\]]')
    app_pattern = re.compile(r'appName\s*=\s*[\'\"\[](.*)[\'\"\]]')
    type_pattern = re.compile(r'vulType\s*=\s*[\'\"\[](.*)[\'\"\]]')
    version_pattern = re.compile(r'appVersion\s*=\s*[\'\"\[](.*)[\'\"\]]')
    desc_pattern = re.compile(r'desc\s*=\s*[\'\"\[](.*)[\'\"\]]')
    service_pattern = re.compile(r'defaultService\s*=\s*[\'\"\[](.*)[\'\"\]]')
    ports_pattern = re.compile(r'defaultPorts\s*=\s*[\'\"\[](.*)[\'\"\]]')
    plugin_data = open(plugin_filename, 'r').read()
    try:
        plugin_name = name_pattern.findall(plugin_data)
        plugin_author = author_pattern.findall(plugin_data)
        plugin_date = date_pattern.findall(plugin_data)
        plugin_app = app_pattern.findall(plugin_data)
        plugin_type = type_pattern.findall(plugin_data)
        plugin_version = version_pattern.findall(plugin_data)
        plugin_desc = desc_pattern.findall(plugin_data)
        default_service = service_pattern.findall(plugin_data)
        default_ports = ports_pattern.findall(plugin_data)

        plugin_info = {
            "plugin_filename": plugin_filename,
            "plugin_name": plugin_name[0],
            "plugin_author": plugin_author[0],
            "plugin_date": plugin_date[0],
            "plugin_app": plugin_app[0],
            "plugin_type": plugin_type[0],
            "plugin_desc": plugin_desc[0],
            "plugin_version": plugin_version[0],
            # "default_service": re.sub(r"[\s\'\"]", '', default_service[0]).split(','),
            "default_service": re.compile("[\'\"](.*)[\'\"]").findall(default_service[0]),
            "default_ports": (default_ports[0]).replace(r' ', '').split(',')
        }
    except Exception as e:
        print "[*] %s" % e
        return False
    return plugin_info


def local_install():
    print("[*]Processing...")
    # connectiondb(plugin_db).drop()
    path = os.getcwd() + '/aquaman/modules/poc_vul/pocsuite_plugin/'
    files = os.listdir(path)

    for file_name in files:
        if 'JBoss' not in file_name:
            continue
        plugin_info = parse_plugin(path + file_name.strip())
        print plugin_info
        if not plugin_info:
            continue
        else:
            # print plugin_info
            db_insert = connectiondb(plugin_db).insert_one(plugin_info).inserted_id
            print db_insert
    print("[*]Processing Completed!")


if __name__ == "__main__":
    local_install()
