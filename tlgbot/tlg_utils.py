import os
import json
import zlib
import time
import base64
import codecs
import string
import hashlib

from datetime import datetime
from tlglogging.config import logger
from tlgconfig.base import BaseConfig
from tlgbot.tlg_banner import tlg_bot_banner

CTI_BOT_MESSAGE = 'CTI_Bot_Message.json'


def data_encode(data: str):
    result = base64.b64encode(zlib.compress(data.encode())).decode()
    checksum = hashlib.sha1(data.encode()).hexdigest()
    return result, checksum


def data_decode(data: str):
    result = zlib.decompress(base64.b64decode(data.encode())).decode()
    checksum = hashlib.sha1(result.encode()).hexdigest()
    return result, checksum


def datetime_to_unix(dt: datetime):
    """ Convert datetime to unix timestamp """
    return time.mktime(dt.timetuple())


def unix_to_datetime(unix_ts: float):
    """ Convert unix timestamp to datetime """
    return datetime.fromtimestamp(unix_ts)


def expire_url_parsing(url):
    import urllib.parse as urlparse
    from urllib.parse import parse_qs
    parsed = urlparse.urlparse(url)
    unix_time = int(parse_qs(parsed.query)['Expires'][0])
    return unix_to_datetime(unix_time).strftime('%Y-%m-%d %H:%M:%S')


def bytes2human(n, format="%(value).2f %(symbol)s"):
    symbols = ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB')
    prefix = {}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i + 1) * 10
    for symbol in reversed(symbols[1:]):
        if n >= prefix[symbol]:
            value = float(n) / prefix[symbol]
            return format % locals()
    return format % dict(symbol=symbols[0], value=n)


def message_format(mes):
    """ Re-format string to telegram code format """
    return "`{}`".format(mes)


def message_load():
    """ Loading Message dictionary from file """
    base_conf = BaseConfig()
    with codecs.open(os.path.join(base_conf.data_dir, CTI_BOT_MESSAGE), 'r', encoding='utf-8') as fr:
        mes = json.load(fr)
    return mes


def schedule_time_validator(ts: str):
    """ ts: %H:%M:%S"""
    try:
        datetime.strptime(ts, '%H:%M:%S')
    except Exception as ex:
        return False
    return True


def hunt_id_validator(hunt_id):
    if len(str(hunt_id)) != 10:
        return False
    if not str(hunt_id).isdigit():
        return False
    return True


# Ref: https://stackoverflow.com/a/51354660
def chat_id_validator(chat_id):
    if len(str(chat_id)) not in range(6, 11):
        return False
    if not str(chat_id).isdigit():
        return False
    return True


# Ref: https://core.telegram.org/method/account.checkUsername
def username_validator(username):
    if len(str(username)) not in range(5, 33):
        return False
    letters = string.ascii_letters + string.digits + '_'
    for chr_ in list(username):
        if chr_ not in letters:
            return False
    return True


def sd_key_validator(key):
    """ Validation Shodan API Key """
    if len(key) != 32:
        return False
    letters = list(string.ascii_letters + string.digits)
    for chr_ in list(key):
        if chr_ not in letters:
            return False
    return True


def zip_id_validator(zip_id):
    if len(zip_id) not in [16]:
        return False
    for chr_ in list(zip_id):
        if chr_ not in string.digits:
            return False
    return True


def vt_key_validator(vt_key):
    """ Validation VirusTotal API Key """
    if len(vt_key) != 64:
        return False
    for chr_ in list(vt_key):
        if chr_ not in string.hexdigits:
            return False
    return True


def hash_validator(value):
    """ Validation Hash Value: MD5, SHA1, SHA256 """
    if len(value) not in [32, 40, 64]:
        return False
    for chr_ in list(value):
        if chr_ not in string.hexdigits:
            return False
    return True


def help_command(update, context):
    """Send a message when the command /help is issued."""
    tlg_bot_banner(update, context)


def echo_message(update, context):
    """Echo the user message."""
    tlg_bot_banner(update, context)


def error_handler(update, context):
    """Log Errors caused by Updates."""
    logger.warning('Update "%s" caused error "%s"', update, context.error)
