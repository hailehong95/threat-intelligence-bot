import json
import vtapi
import tlgconfig
from tlgbot.tlg_sqlite import *
from tlglogging.config import logger
from tlgbot.tlg_utils import vt_key_validator
from tlgbot.tlg_banner import key_manager_banner
from tlgbot.tlg_utils import message_load, message_format

ONE_ARGS = ['dump', 'export', 'del']
TWO_ARGS = ['add', 'del', 'enable', 'dump']
mess = message_load()['key_manager']


def command_validator(update, context):
    try:
        args_len = len(context.args)
        if args_len == 0:
            key_manager_banner(update, context)
            return
        elif args_len == 1:
            arg_0 = str(context.args[0])
            if arg_0 == 'help':
                key_manager_banner(update, context)
                return
            if arg_0 not in ONE_ARGS:
                update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                return
        elif args_len == 2:
            arg_0 = str(context.args[0])
            arg_1 = str(context.args[1])
            if arg_0 not in TWO_ARGS:
                update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                return
            else:
                if not vt_key_validator(arg_1):
                    update.message.reply_text(message_format(mess['error_vt_key']), parse_mode='MarkdownV2')
                    return
        else:
            update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
            return
    except Exception as ex:
        logger.warning(str(ex))
    return True


def key_manager_handler(update, context):
    try:
        if not command_validator(update, context):
            return
        cmd = str(context.args[0])
        return {
            'add': key_add,
            'del': key_del,
            'dump': key_dump,
            'enable': key_enable,
            'export': key_export
        }.get(cmd)(update, context)
    except Exception as ex:
        logger.warning(str(ex))


def key_add(update, context):
    try:
        input_key = str(context.args[1])
        chat_id = update.message.chat_id
        username = update.message.chat.username
        is_exist = vt_users_search_one_key(chat_id, input_key)
        if is_exist:
            update.message.reply_text(message_format(mess['error_exist_key']), parse_mode='MarkdownV2')
            return
        vt_etp = vtapi.VirusTotalAPIEnterprise(input_key)
        response = vt_etp.get_user(input_key)
        if vt_etp.get_last_http_error() == vt_etp.HTTP_OK:
            is_private = json.loads(response)['data']['attributes']['privileges']['private']['granted']
            key_item = {
                "api_key": input_key,
                "chat_id": chat_id,
                "username": username,
                "is_private": is_private,
                "is_enable": False
            }
            if vt_users_add_key(key_item):
                update.message.reply_text(message_format(mess['success_add_key']), parse_mode='MarkdownV2')
            else:
                update.message.reply_text(message_format(mess['error_add_key']), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_vt_key']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def key_dump(update, context):
    try:
        args_len = len(context.args)
        chat_id = update.message.chat_id
        user_keys = vt_users_search_multi_key(chat_id)
        if not user_keys:
            update.message.reply_text(message_format(mess['error_empty_keys']), parse_mode='MarkdownV2')
            return
        if args_len == 1:
            markdown_mes = message_format(str(json.dumps(user_keys, sort_keys=False, indent=4)))
            markdown_mes += "\n\n" + message_format("TỔNG SỐ KHÓA: %d" % len(user_keys))
            update.message.reply_text(markdown_mes, parse_mode='MarkdownV2')
        if args_len == 2:
            input_vt_key = str(context.args[1])
            for key in user_keys:
                if key.get("api_key") == input_vt_key:
                    markdown_mes = message_format(str(json.dumps(key, sort_keys=False, indent=4)))
                    update.message.reply_text(markdown_mes, parse_mode='MarkdownV2')
                    return
            update.message.reply_text(message_format(mess['error_missing_key']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def key_del(update, context):
    try:
        args_len = len(context.args)
        chat_id = update.message.chat_id
        vt_keys = vt_users_search_multi_key(chat_id)
        if not vt_keys:
            update.message.reply_text(message_format(mess['error_empty_keys']), parse_mode='MarkdownV2')
            return
        if args_len == 1:
            if vt_users_del_multi_key(chat_id):
                update.message.reply_text(message_format(mess['success_delete_keys']), parse_mode='MarkdownV2')
            else:
                update.message.reply_text(message_format(mess['error_delete_keys']), parse_mode='MarkdownV2')
        if args_len == 2:
            input_key = str(context.args[1])
            for key in vt_keys:
                if key['api_key'] == input_key:
                    if vt_users_del_one_key(chat_id, input_key):
                        update.message.reply_text(message_format(mess['success_delete_key']), parse_mode='MarkdownV2')
                        return
                    else:
                        update.message.reply_text(message_format(mess['error_delete_key']), parse_mode='MarkdownV2')
                        return
            update.message.reply_text(message_format(mess['error_missing_key']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def key_enable(update, context):
    try:
        input_key = str(context.args[1])
        chat_id = update.message.chat_id
        vt_key = vt_users_search_one_key(chat_id, input_key)
        if not vt_key:
            update.message.reply_text(message_format(mess['error_missing_key']), parse_mode='MarkdownV2')
            return
        if vt_users_set_enabled_key(chat_id, input_key):
            update.message.reply_text(message_format(mess['success_enable_key']), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_enable_key']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def key_export(update, context):
    try:
        chat_id = update.message.chat_id
        vt_keys = vt_users_search_multi_key(chat_id)
        if not vt_keys:
            update.message.reply_text(message_format(mess['error_empty_keys']), parse_mode='MarkdownV2')
            return
        data = json.dumps(vt_keys, sort_keys=False, indent=4).encode('utf-8')
        filename = str(chat_id) + '.json'
        context.bot.send_document(chat_id=chat_id, document=data, filename=filename)
    except Exception as ex:
        logger.warning(str(ex))
