# -*- coding: utf-8 -*-
import logging
import sys
from os import makedirs
from os.path import dirname, exists
# from application.config import TASK_SCHEDULE_LOG_DIR, LOG_LEVEL
from application import settings
import time

loggers = {}
LOG_LEVEL = settings.LOG_LEVEL
LOG_PATH = settings.TASK_SCHEDULE_LOG_DIR + time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime()) + '.log'
LOG_ENABLED = True  # 是否开启日志
LOG_TO_CONSOLE = False  # 是否输出到控制台
LOG_TO_FILE = True  # 是否输出到文件
LOG_FORMAT = '[%(asctime)s] - %(levelname)s - process: %(process)d - %(filename)s - %(name)s - %(lineno)d - %(module)s - %(message)s'  # 每条日志输出格式
ELASTIC_SEARCH_INDEX = 'runtime'  # Elasticsearch Index Name
APP_ENVIRONMENT = 'dev'  # 运行环境，如测试环境还是生产环境


def get_logger(name=None):
    """
    get logger by name
    :param name: name of logger
    :return: logger
    """
    global loggers

    if not name:
        name = __name__

    if loggers.get(name):
        return loggers.get(name)

    logger = logging.getLogger(name)
    logger.setLevel(LOG_LEVEL)

    # 输出到控制台
    if LOG_ENABLED and LOG_TO_CONSOLE:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setLevel(level=LOG_LEVEL)
        formatter = logging.Formatter(LOG_FORMAT)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    # 输出到文件
    if LOG_ENABLED and LOG_TO_FILE:
        # 如果路径不存在，创建日志文件文件夹
        log_dir = dirname(LOG_PATH)
        if not exists(log_dir):
            makedirs(log_dir)
        # 添加 FileHandler
        file_handler = logging.FileHandler(LOG_PATH, encoding='utf-8')
        file_handler.setLevel(level=LOG_LEVEL)
        formatter = logging.Formatter(LOG_FORMAT)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # 保存到全局 loggers
    loggers[name] = logger
    return logger


if __name__ == "__main__":
    a = get_logger()
    a.info('xxx')
    a.error('yyy')
