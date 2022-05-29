#!/usr/bin/env python
import os
import time

from tlglogging.config import logger


def test_logger():
    logger.info("Hello info")
    logger.critical("Hello critical")
    logger.warning("Hello warning")
    logger.debug("Hello debug")
    logger.exception("Hello Exception")
    # for i in range(0, 100):
    #     logger.info("This is Step %d" % i)
    #     time.sleep(3)
    pass


def test_logging_path():
    from tlgconfig.base import BaseConfig
    bc = BaseConfig()
    log_path = os.path.join(bc.data_dir, 'threat-intelligence-bot.log')
    print(log_path)
