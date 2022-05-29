import json
import time
import vtapi
import validators
from datetime import datetime, timedelta

from tlgbot.tlg_sqlite import *
from tlglogging.config import logger
from tlgbot.tlg_banner import vip_member_banner, vip_admin_banner
from tlgbot.tlg_utils import username_validator, chat_id_validator, datetime_to_unix
from tlgbot.tlg_utils import message_load, message_format, bytes2human, unix_to_datetime
from tlgbot.tlg_utils import hash_validator, vt_key_validator, expire_url_parsing

VIP_MEMBER = ['dl', 'si']
VIP_ADMIN = ['day', 'req', 'ren', 'del', 'dump']
VIP_ADMIN_ONE = ['dump', 'log']
VIP_ADMIN_TWO = ['dump', 'log']
VIP_ADMIN_THREE = ['del']
VIP_ADMIN_FOUR = ['day', 'req', 'ren']
SI_LIMIT = 20
MAX_LOGS_RECORD = 20
mess = message_load()['vip_member']


def vip_member_init(update, context):
    try:
        vt_key = ""
        is_enable = is_private = False
        chat_id = update.message.chat_id
        user_key = vt_users_get_enabled_key(chat_id)
        if user_key:
            is_enable = True
            vt_key = user_key.get("api_key")
            if user_key.get("is_private") == 1:
                is_private = True
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return is_enable, is_private, vt_key


def command_validator(update, context):
    try:
        args_len = len(context.args)
        is_enable, is_private, vt_key = vip_member_init(update, context)
        if not is_enable:
            update.message.reply_text(message_format(mess['error_enable_key']), parse_mode='MarkdownV2')
            return

        # Public Key scope
        if not is_private:
            # /vip | Show Member banner
            if args_len == 0:
                vip_member_banner(update, context)
                return
            elif args_len == 1:
                arg_0 = str(context.args[0])
                # /vip help
                if arg_0 == 'help':
                    vip_member_banner(update, context)
                    return
                else:
                    update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                    return
            elif args_len == 2:
                arg_0 = str(context.args[0])
                arg_1 = str(context.args[1])
                if arg_0 not in VIP_MEMBER:
                    update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                    return
                else:
                    # /vip dl <hash/url>
                    if arg_0 == "dl":
                        if (not hash_validator(arg_1)) and (not validators.url(arg_1)):
                            update.message.reply_text(message_format(mess['error_invalid_hash']), parse_mode='MarkdownV2')
                            return
                    # /vip si <query>
                    if arg_0 == "si":
                        return True
            else:
                # Multi args
                arg_0 = str(context.args[0])
                if arg_0 == "si":
                    return True
                else:
                    # /vip <arg_0> <arg_1> <arg_2> ... <arg_n>
                    update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                    return
        else:
            # Private Key scope
            if args_len == 0:
                # /vip | Show Admin banner
                vip_admin_banner(update, context)
                return
            elif args_len == 1:
                arg_0 = str(context.args[0])
                if arg_0 == 'help':
                    vip_admin_banner(update, context)
                    return
                if arg_0 not in VIP_ADMIN_ONE:
                    update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                    return
            elif args_len == 2:
                arg_0 = str(context.args[0])
                if arg_0 not in VIP_ADMIN_TWO:
                    update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                    return
                else:
                    # /vip dump [key]
                    if arg_0 == 'dump':
                        key = str(context.args[1])
                        if not vt_key_validator(key):
                            update.message.reply_text(message_format(mess['error_vt_key']), parse_mode='MarkdownV2')
                            return
                    # /vip log [username]
                    elif arg_0 == 'log':
                        username = str(context.args[1])
                        if not username_validator(username):
                            update.message.reply_text(message_format(mess['error_username']), parse_mode='MarkdownV2')
                            return
            elif args_len == 3:
                # /vip del <key> <chat_id>
                arg_0 = str(context.args[0])
                if arg_0 not in VIP_ADMIN_THREE:
                    update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                    return
                else:
                    arg_1 = str(context.args[1])
                    if not vt_key_validator(arg_1):
                        update.message.reply_text(message_format(mess['error_vt_key']), parse_mode='MarkdownV2')
                        return
                    chat_id = str(context.args[2])
                    if not chat_id_validator(chat_id):
                        update.message.reply_text(message_format(mess['error_chat_id']), parse_mode='MarkdownV2')
                        return
            elif args_len == 4:
                arg_0 = str(context.args[0])
                if arg_0 not in VIP_ADMIN_FOUR:
                    update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                    return
                else:
                    # /vip day <number> <key> <chat_id>, /vip req <number> <key> <chat_id>
                    number = str(context.args[1])
                    if not number.isdigit():
                        update.message.reply_text(message_format(mess['error_number']), parse_mode='MarkdownV2')
                        return
                    key = str(context.args[2])
                    if not vt_key_validator(key):
                        update.message.reply_text(message_format(mess['error_vt_key']), parse_mode='MarkdownV2')
                        return
                    chat_id = str(context.args[3])
                    if not chat_id_validator(chat_id):
                        update.message.reply_text(message_format(mess['error_chat_id']), parse_mode='MarkdownV2')
                        return
            else:
                update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                return
    except Exception as ex:
        logger.warning(str(ex))
    return True


def vip_member_handler(update, context):
    try:
        if not command_validator(update, context):
            return

        _, is_private, vt_key = vip_member_init(update, context)
        if is_private:
            cmd = str(context.args[0])
            return {
                'day': vip_add_day,
                'req': vip_add_request,
                'ren': vip_renew_vip,
                'del': vip_del,
                'dump': vip_dump,
                'log': vip_log
            }.get(cmd)(update, context, vt_key)
        else:
            cmd = str(context.args[0])
            return {
                'dl': vip_download,
                'si': vip_search_intelligence
            }.get(cmd)(update, context, vt_key)
    except Exception as ex:
        logger.warning(str(ex))


def vip_add_day(update, context, vt_key):
    try:
        member_key = str(context.args[2])
        member_chat_id = str(context.args[3])
        admin_chat_id = update.message.chat_id
        # Check member is exist on system?
        member_on_system = vt_users_search_one_key(member_chat_id, member_key, to_dict=True)
        if not member_on_system:
            update.message.reply_text(message_format(mess['error_member_not_found']), parse_mode='MarkdownV2')
            return
        # Check member has private key
        member_on_system = member_on_system[0]
        if member_on_system.get("is_private") == 1:
            update.message.reply_text(message_format(mess['error_member_private_key']), parse_mode='MarkdownV2')
            return
        # Check member available before
        vip_member_exist = vip_member_check_exist(member_chat_id, member_key, admin_chat_id)
        if vip_member_exist:
            update.message.reply_text(message_format(mess['error_member_exist']), parse_mode='MarkdownV2')
            return
        # Add new vip member
        num_of_days = int(str(context.args[1]))
        member_start_time = datetime.now()
        member_end_time = member_start_time + timedelta(days=num_of_days)
        admin_key = vt_key
        admin_username = update.message.chat.username
        member_obj = {
            'member_key': member_key,
            'member_chat_id': member_chat_id,
            'member_username': member_on_system.get("username"),
            'member_start_time': int(datetime_to_unix(member_start_time)),
            'member_end_time': int(datetime_to_unix(member_end_time)),
            'member_is_query': False,
            'admin_key': admin_key,
            'admin_username': admin_username,
            'admin_chat_id': admin_chat_id
        }
        if vip_member_add_by_days(member_obj):
            update.message.reply_text(message_format(mess['success_member_added']), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_member_added']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def vip_add_request(update, context, vt_key):
    try:
        member_chat_id = str(context.args[3])
        admin_chat_id = update.message.chat_id
        member_key = str(context.args[2])
        # Check member is exist on system?
        member_on_system = vt_users_search_one_key(member_chat_id, member_key, to_dict=True)
        if not member_on_system:
            update.message.reply_text(message_format(mess['error_member_not_found']), parse_mode='MarkdownV2')
            return
        # Check member has private key
        member_on_system = member_on_system[0]
        if member_on_system.get("is_private") == 1:
            update.message.reply_text(message_format(mess['error_member_private_key']), parse_mode='MarkdownV2')
            return
        # Check member available before
        vip_member_exist = vip_member_check_exist(member_chat_id, member_key, admin_chat_id)
        if vip_member_exist:
            update.message.reply_text(message_format(mess['error_member_exist']), parse_mode='MarkdownV2')
            return
        # Add new vip member
        num_of_reqs = int(str(context.args[1]))
        admin_key = vt_key
        admin_username = update.message.chat.username
        member_obj = {
            'member_key': member_key,
            'member_chat_id': member_chat_id,
            'member_username': member_on_system.get("username"),
            'member_query_used': 0,
            'member_query_allowed': num_of_reqs,
            'member_is_query': True,
            'admin_key': admin_key,
            'admin_username': admin_username,
            'admin_chat_id': admin_chat_id
        }
        if vip_member_add_by_requests(member_obj):
            update.message.reply_text(message_format(mess['success_member_added']), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_member_added']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def vip_renew_vip(update, context, vt_key):
    try:
        numbers = int(str(context.args[1]))
        admin_chat_id = update.message.chat_id
        member_key = str(context.args[2])
        member_chat_id = str(context.args[3])
        # Check member is exist on system?
        member_on_system = vip_member_check_exist(member_chat_id, member_key, admin_chat_id, True)
        if not member_on_system:
            update.message.reply_text(message_format(mess['error_member_added']), parse_mode='MarkdownV2')
            return
        # renew vip license for member
        member_on_system = member_on_system[0]
        member_is_query = member_on_system.get("member_is_query")
        if member_is_query == 1:
            old_member_query_allowed = member_on_system.get("member_query_allowed")
            new_member_query_allowed = old_member_query_allowed + numbers
            if vip_member_renew(member_key, admin_chat_id, member_chat_id, new_member_query_allowed, True):
                update.message.reply_text(message_format(mess['success_renew_vip']), parse_mode='MarkdownV2')
            else:
                update.message.reply_text(message_format(mess['error_renew_vip']), parse_mode='MarkdownV2')
        else:
            old_member_end_time = unix_to_datetime(member_on_system.get("member_end_time"))
            new_member_end_time = datetime_to_unix(old_member_end_time + timedelta(days=numbers))
            if vip_member_renew(member_key, admin_chat_id, member_chat_id, new_member_end_time, False):
                update.message.reply_text(message_format(mess['success_renew_vip']), parse_mode='MarkdownV2')
            else:
                update.message.reply_text(message_format(mess['error_renew_vip']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def vip_del(update, context, vt_key):
    try:
        member_key = str(context.args[1])
        member_chat_id = str(context.args[2])
        admin_chat_id = update.message.chat_id
        # Check member available before
        is_exist = vip_member_check_exist(member_chat_id, member_key, admin_chat_id)
        if not is_exist:
            update.message.reply_text(message_format(mess['error_member_not_granted']), parse_mode='MarkdownV2')
            return
        if vip_member_del_key(member_chat_id, member_key, admin_chat_id):
            update.message.reply_text(message_format(mess['success_member_delete']), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_member_delete']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def vip_dump(update, context, vt_key):
    try:
        args_len = len(context.args)
        args_0 = str(context.args[0])
        admin_chat_id = update.message.chat_id
        vip_member_on_system = vip_member_get_all(admin_chat_id)
        if not vip_member_on_system:
            update.message.reply_text(message_format(mess['error_member_empty']), parse_mode='MarkdownV2')
            return
        vip_members_dump = []
        for member in vip_member_on_system:
            item = {
                "vt_key": member.get("member_key"),
                "chat_id": member.get("member_chat_id"),
                "username": member.get("member_username"),
            }
            if member.get("member_is_query") == 1:
                item["vip_type"] = "req"
                item["vip_used"] = member.get("member_query_used")
                item["vip_allowed"] = member.get("member_query_allowed")
            else:
                item["vip_type"] = "day"
                item["vip_start"] = unix_to_datetime(member['member_start_time']).strftime('%Y-%m-%d %H:%M:%S')
                item["vip_end"] = unix_to_datetime(member['member_end_time']).strftime('%Y-%m-%d %H:%M:%S')
            vip_members_dump.append(item)

        # Send message to user
        if args_len == 1:
            text = json.dumps(vip_members_dump, sort_keys=False, indent=4)
            text += "\n\nTỔNG SỐ MEMBER: %d" % len(vip_members_dump)
            update.message.reply_text(message_format(text), parse_mode='MarkdownV2')
            return
        if args_len == 2:
            input_key = str(context.args[1])
            for member in vip_members_dump:
                if member.get("vt_key") == input_key:
                    text = json.dumps(member, sort_keys=False, indent=4)
                    update.message.reply_text(message_format(text), parse_mode='MarkdownV2')
                    return
    except Exception as ex:
        logger.warning(str(ex))


def vip_log(update, context, vt_key):
    try:
        args_len = len(context.args)
        args_0 = str(context.args[0])
        admin_chat_id = update.message.chat_id
        logs_data = dict()
        if args_len == 1:
            if args_0 in VIP_ADMIN_ONE:
                logs_data = vip_member_logs_get(admin_chat_id=admin_chat_id, limit=MAX_LOGS_RECORD)
        elif args_len == 2:
            if args_0 in VIP_ADMIN_TWO:
                member_username = str(context.args[1])
                logs_data = vip_member_logs_get(admin_chat_id=admin_chat_id, member_username=member_username, limit=MAX_LOGS_RECORD)
        if not logs_data:
            update.message.reply_text(message_format(mess['error_logs_empty']), parse_mode='MarkdownV2')
            return
        logs_data_sorted = sorted(logs_data, key=lambda k: k['create_time'])
        for item in logs_data_sorted:
            item['create_time'] = unix_to_datetime(item['create_time']).strftime('%Y-%m-%d %H:%M:%S')
            if item['member_logs_status'] == 0:
                item['member_logs_status'] = False
            else:
                item['member_logs_status'] = True
        batch_size = 5
        for i in range(0, len(logs_data_sorted), batch_size):
            batch = logs_data_sorted[i:i + batch_size]
            markdown_mes = message_format(str(json.dumps(batch, sort_keys=False, indent=4)))
            update.message.reply_text(markdown_mes, parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def vip_download(update, context, vt_key):
    try:
        member_key = vt_key
        member_chat_id = update.message.chat_id
        vip_members = vip_member_get_private_keys(member_chat_id, member_key)
        if not vip_members:
            update.message.reply_text(message_format(mess['error_member_added']), parse_mode='MarkdownV2')
            return
        # Get private key (admin key) of member
        private_keys = []
        for member in vip_members:
            key_obj = dict()
            if member.get("member_is_query") == 1:
                q_used = int(member.get("member_query_used"))
                q_allowed = int(member.get("member_query_allowed"))
                if q_used < q_allowed:
                    key_obj['member_is_query'] = True
                    key_obj['admin_key'] = member['admin_key']
                    key_obj['admin_chat_id'] = member['admin_chat_id']
                    private_keys.append(key_obj)
            else:
                time_now = int(datetime_to_unix(datetime.now()))
                m_start_time = int(member.get("member_start_time"))
                m_end_time = int(member.get("member_end_time"))
                if m_start_time < time_now < m_end_time:
                    key_obj['member_is_query'] = False
                    key_obj['admin_key'] = member['admin_key']
                    key_obj['admin_chat_id'] = member['admin_chat_id']
                    private_keys.append(key_obj)
        if not private_keys:
            update.message.reply_text(message_format(mess['error_member_expired']), parse_mode='MarkdownV2')
            return
        # Get input hash or url from user
        arg_list = context.args
        input_hashes = []
        for item in arg_list[1:]:
            if hash_validator(item):
                input_hashes.append(item)
            elif validators.url(item):
                for tok in item.split('/'):
                    if hash_validator(tok):
                        input_hashes.append(tok)
        input_hashes = list(set(input_hashes))
        if not input_hashes:
            update.message.reply_text(message_format(mess['error_missing_hash_url']), parse_mode='MarkdownV2')
            return
        # Get file from VT
        file_id = input_hashes[0]
        private_keys = private_keys[0]
        admin_key = private_keys.get("admin_key")
        member_is_query = private_keys.get("member_is_query")
        admin_chat_id = private_keys.get("admin_chat_id")
        member_chat_id = update.message.chat_id
        member_username = update.message.chat.username
        vt_vip_member = vtapi.VirusTotalAPIEnterprise(admin_key)
        try:
            resp = vt_vip_member.get_download_url(file_id)
        except Exception as ex:
            logger.warning('get_download_url - ' + str(ex))
        else:
            resp = json.loads(resp)
            if vt_vip_member.get_last_http_error() == vt_vip_member.HTTP_OK:
                dl_item = {
                    "hash": file_id,
                    "download": "<a href='%s'>link</a>" % resp.get("data"),
                    "expires_on": expire_url_parsing(resp.get("data"))
                }
                message_data = json.dumps(dl_item, sort_keys=False, indent=4)
                member_logs = "/vip dl %s" % file_id
                log_item = {
                    "member_chat_id": member_chat_id,
                    "member_username": member_username,
                    "member_key": member_key,
                    "admin_chat_id": admin_chat_id,
                    "member_logs": member_logs
                }
                if member_is_query:
                    if vip_member_increment_query(member_chat_id, admin_key, member_key):
                        update.message.reply_text(message_data, parse_mode='HTML')
                        log_item["member_logs_status"] = True
                        vip_member_logs_post(log_item)
                    else:
                        update.message.reply_text(message_format(mess['error_send_file']), parse_mode='MarkdownV2')
                        log_item["member_logs_status"] = False
                        vip_member_logs_post(log_item)
                else:
                    update.message.reply_text(message_data, parse_mode='HTML')
                    log_item["member_logs_status"] = True
                    vip_member_logs_post(log_item)
            else:
                err_item = {
                    "hash": file_id,
                    "download": resp["error"].get("code")
                }
                md_response = json.dumps(err_item, sort_keys=False, indent=4)
                update.message.reply_text(message_format(md_response), parse_mode='HTML')
    except Exception as ex:
        logger.warning(str(ex))


def vip_search_intelligence(update, context, vt_key):
    try:
        member_key = vt_key
        member_chat_id = update.message.chat_id
        private_keys = []
        vip_members = vip_member_get_private_keys(member_chat_id, member_key)
        if not vip_members:
            update.message.reply_text(message_format(mess['error_member_added']), parse_mode='MarkdownV2')
            return
        # Get private key (admin key) of member
        for member in vip_members:
            key_obj = dict()
            if member.get("member_is_query") == 1:
                q_used = int(member.get("member_query_used"))
                q_allowed = int(member.get("member_query_allowed"))
                if q_used < q_allowed:
                    key_obj["member_is_query"] = True
                    key_obj["admin_key"] = member.get("admin_key")
                    key_obj["admin_chat_id"] = member.get("admin_chat_id")
                    private_keys.append(key_obj)
            else:
                time_now = int(datetime_to_unix(datetime.now()))
                m_start_time = int(member.get("member_start_time"))
                m_end_time = int(member.get("member_end_time"))
                if m_start_time < time_now < m_end_time:
                    key_obj["member_is_query"] = False
                    key_obj["admin_key"] = member.get("admin_key")
                    key_obj["admin_chat_id"] = member.get("admin_chat_id")
                    private_keys.append(key_obj)
        if not private_keys:
            update.message.reply_text(message_format(mess['error_member_expired']), parse_mode='MarkdownV2')
            return
        # Search Intelligence on VT
        private_keys = private_keys[0]
        arg_list = context.args
        admin_key = private_keys.get("admin_key")
        member_is_query = private_keys.get("member_is_query")
        admin_chat_id = private_keys.get("admin_chat_id")
        member_chat_id = update.message.chat_id
        member_username = update.message.chat.username
        input_query = " ".join(arg_list[1:])
        try:
            vt_vip_member = vtapi.VirusTotalAPIEnterprise(admin_key)
            result = vt_vip_member.intelligence_file_search(query=input_query, descriptors_only=False, limit=SI_LIMIT)
        except Exception as ex:
            logger.warning('intelligence_file_search - ' + str(ex))
        else:
            if vt_vip_member.get_last_http_error() == vt_vip_member.HTTP_OK:
                temp = json.loads(result)
                si_data = temp.get("data")
                member_logs = "/vip si %s" % input_query
                log_item = {
                    "member_chat_id": member_chat_id,
                    "member_username": member_username,
                    "member_key": member_key,
                    "admin_chat_id": admin_chat_id,
                    "member_logs": member_logs
                }
                # Check intelligence data exist
                if not si_data:
                    update.message.reply_text(message_format(mess['error_empty_result']), parse_mode='MarkdownV2')
                    log_item["member_logs_status"] = False
                    vip_member_logs_post(log_item)
                    return
                # intelligence data exist
                if member_is_query:
                    is_incremented = vip_member_increment_query(member_chat_id, admin_key, member_key)
                    if not is_incremented:
                        log_item["member_logs_status"] = False
                        vip_member_logs_post(log_item)
                        update.message.reply_text(message_format(mess['error_send_message']), parse_mode='MarkdownV2')
                        return
                # send data message
                batch_size = 2
                for i in range(0, len(si_data), batch_size):
                    batch = si_data[i:i + batch_size]
                    batch_data = []
                    for item in batch:
                        malicious = item["attributes"]["last_analysis_stats"]["malicious"]
                        undetected = item["attributes"]["last_analysis_stats"]["undetected"]
                        fs_date = item["attributes"]["first_submission_date"]
                        ls_date = item["attributes"]["last_submission_date"]
                        obj_data = {
                            "sha256": item["attributes"]["sha256"],
                            "detection": "{}/{}".format(malicious, malicious + undetected),
                            "meaningful_name": item["attributes"].get("meaningful_name", ""),
                            "size": bytes2human(item["attributes"]["size"]),
                            "type_description": item["attributes"]["type_description"],
                            "first_submission_date": unix_to_datetime(fs_date).strftime('%Y-%m-%d %H:%M:%S'),
                            "last_submission_date": unix_to_datetime(ls_date).strftime('%Y-%m-%d %H:%M:%S'),
                            "exiftool": str(item["attributes"].get("exiftool", ""))
                        }
                        batch_data.append(obj_data)
                    batch_text = json.dumps(batch_data, sort_keys=False, indent=4)
                    update.message.reply_text(message_format(batch_text), parse_mode='MarkdownV2')
                log_item["member_logs_status"] = True
                vip_member_logs_post(log_item)
            else:
                text = vt_vip_member.get_last_result()
                markdown_text = message_format(json.loads(text))
                update.message.reply_text(markdown_text, parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))
