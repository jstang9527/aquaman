# coding=utf-8
import sys
sys.path.append('/home/aquaman')
from pymongo import MongoClient
from application import settings


# 一个collection一个连接
def connectiondb(collection):
    client = MongoClient(settings.DB_HOST, settings.DB_PORT)
    db = client[settings.DB_NAME]
    db.authenticate(settings.DB_USERNAME, settings.DB_PASSWORD)
    dbcollection = db[collection]
    return dbcollection


# 多个collection一个连接
def connectiondb2(info):
    print "[*] New Mongo Conn({})".format(info)
    client = MongoClient(settings.DB_HOST, settings.DB_PORT, connect=False)
    db = client[settings.DB_NAME]
    db.authenticate(settings.DB_USERNAME, settings.DB_PASSWORD)
    return db


def db_management(command):
    client = MongoClient(settings.DB_HOST, settings.DB_PORT)
    db = client[settings.DB_NAME]
    db.authenticate(settings.DB_USERNAME, settings.DB_PASSWORD)
    if command == 'collection_names':
        result = db.collection_names()
        return result


def db_name_conf():
    asset_db = settings.ASSET_DB
    tasks_db = settings.TASKS_DB
    cus_db = settings.CUS_DB
    vul_db = settings.VULNERABILITY_DB
    plugin_db = settings.PLUGIN_DB
    config_db = settings.CONFIG_DB
    server_db = settings.SERVER_DB
    subdomain_db = settings.SUBDOMAIN_DB
    domain_db = settings.DOMAIN_DB
    weekpasswd_db = settings.WEEKPASSWD_DB
    port_db = settings.PORT_DB
    auth_db = settings.AUTH_DB
    vulscan_db = settings.VULSCAN_DB
    instance_db = settings.INSTANCE_DB
    portinfo_db = settings.PORTINFO_DB
    exploit_db = settings.EXPLOIT_DB
    discovery_db = settings.DISCOVERY_DB

    db_name_dict = {
        'asset_db': asset_db,
        'tasks_db': tasks_db,
        'cus_db': cus_db,
        'vul_db': vul_db,
        'plugin_db': plugin_db,
        'config_db': config_db,
        'server_db': server_db,
        'subdomain_db': subdomain_db,
        'domain_db': domain_db,
        'weekpasswd_db': weekpasswd_db,
        'port_db': port_db,
        'auth_db': auth_db,
        'vulscan_db': vulscan_db,
        'instance_db': instance_db,
        'portinfo_db': portinfo_db,
        'exploit_db': exploit_db,
        'discovery_db': discovery_db,
    }
    return db_name_dict


mongo_cli = connectiondb2('global')


if __name__ == "__main__":
    print db_management('collection_names')
