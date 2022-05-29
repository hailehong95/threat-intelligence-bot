# Ref: https://stackoverflow.com/a/63338866
import os
import sys
import logging

from tlgconfig.base import BaseConfig

logger = logging.getLogger()
# logger.setLevel(logging.INFO)
logFormatter = logging.Formatter('%(asctime)s - %(filename)s.%(funcName)s:%(lineno)d - %(levelname)s: %(message)s',
                                 datefmt='%a %Y-%m-%d %H:%M:%S')

bc = BaseConfig()
file_name = 'CTI_Bot.log'
log_path = os.path.join(bc.data_dir, file_name)
fileHandler = logging.FileHandler(log_path)
fileHandler.setLevel(logging.INFO)
fileHandler.setFormatter(logFormatter)
logger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler(sys.stdout)
consoleHandler.setLevel(logging.INFO)
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)
