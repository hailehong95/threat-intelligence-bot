import json
import vtapi

from tlglogging.config import logger
from tlgbot.tlg_banner import ip_address_banner
from tlgbot.tlg_sqlite import vt_users_get_enabled_key
from tlgbot.tlg_utils import message_load, message_format
from tlgbot.tlg_utils import hash_validator, zip_id_validator
mess = message_load()['ip_address']


def command_validator(update, context):
    args_len = len(context.args)
    if args_len == 0:
        ip_address_banner(update, context)
        return False
    elif args_len == 1:
        arg_0 = str(context.args[0])
        if arg_0 == 'help':
            ip_address_banner(update, context)
            return False
        pass
    elif args_len == 2:
        arg_0 = str(context.args[0])
        arg_1 = str(context.args[1])
        pass
    else:
        pass
    return True


def ip_address_init(update, context):
    chat_id = update.message.chat_id
    key_info = vt_users_get_enabled_key(chat_id)
    if key_info:
        return True, key_info['api_key']
    else:
        update.message.reply_text(message_format(mess['error_enable_key']), parse_mode='MarkdownV2')
    return False, None


def ip_address_handler(update, context):
    try:
        if command_validator(update, context):
            pass
    except Exception as ex:
        logger.warning(str(ex))
