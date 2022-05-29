import json
import pytz
import vtapi
import requests
import iocextract
import validators

from time import sleep
from datetime import datetime, time
from tlgbot.tlg_sqlite import *
from tlglogging.config import logger
from tlgbot.tlg_banner import hunting_banner
from tlgbot.tlg_utils import data_encode, data_decode, schedule_time_validator
from tlgbot.tlg_utils import hash_validator, message_format, message_load
from tlgbot.tlg_utils import unix_to_datetime, datetime_to_unix, hunt_id_validator

HUNT_ONE = ['dump', 'start', 'stop', 'status', 'export']
HUNT_MULTI = ['si', 'hash', 'update', 'stime']
HUNT_TWO = ['hash', 'url', 'si', 'dump', 'del', 'log', 'update']
ADMIN_ID = ['', '']  # Add your Telegram ChatID
MAX_HASH = 50
MAX_HASH_EXPORT = 100
mess = message_load()['hunting']


def hunting_init(update, context):
    try:
        vt_key = ""
        is_enable = is_private = is_admin = False
        chat_id = update.message.chat_id
        user_key = vt_users_get_enabled_key(chat_id)
        if user_key:
            is_enable = True
            if user_key.get("is_private") == 1:
                is_private = True
                vt_key = user_key.get("api_key")
                if user_key.get("chat_id") in ADMIN_ID:
                    is_admin = True
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return is_enable, is_private, is_admin, vt_key


def command_validator(update, context):
    try:
        is_enable, is_private, is_admin, vt_key = hunting_init(update, context)
        if not is_enable:
            update.message.reply_text(message_format(mess['error_enable_key']), parse_mode='MarkdownV2')
            return
        if not is_private:
            update.message.reply_text(message_format(mess['error_permission_key']), parse_mode='MarkdownV2')
            return
        if not is_admin:
            update.message.reply_text(message_format(mess['error_permission_user']), parse_mode='MarkdownV2')
            return
        args_len = len(context.args)
        if args_len == 0:
            hunting_banner(update, context)
            return
        elif args_len == 1:
            arg_0 = str(context.args[0])
            if arg_0 == 'help':
                hunting_banner(update, context)
                return
            if arg_0 not in HUNT_ONE:
                update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                return
        elif args_len == 2:
            arg_0 = str(context.args[0])
            arg_1 = str(context.args[1])
            if arg_0 not in HUNT_TWO:
                update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                return
            else:
                # /hunt hash <hash>
                if arg_0 == "hash":
                    if not hash_validator(arg_1):
                        update.message.reply_text(message_format(mess['error_invalid_hash']), parse_mode='MarkdownV2')
                        return
                # /hunt url <url>
                if arg_0 == "url":
                    if not validators.url(arg_1):
                        update.message.reply_text(message_format(mess['error_invalid_url']), parse_mode='MarkdownV2')
                        return
                # /hunt si <query>
                if arg_0 == "si":
                    return True
                # /hunt dump|del|log|update
                if arg_0 in ['dump', 'del', 'log', 'update']:
                    if not hunt_id_validator(arg_1):
                        update.message.reply_text(message_format(mess['error_invalid_hunt_id']), parse_mode='MarkdownV2')
                        return
        else:
            arg_0 = str(context.args[0])
            arg_list = context.args
            if arg_0 not in HUNT_MULTI:
                update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                return
            else:
                # /hunt si <query>
                if arg_0 == "si":
                    return True
                # /hunt hash <md5,sha1,sha256>
                if arg_0 == "hash":
                    input_hashes = list(set(arg_list[1:]))
                    if len(input_hashes) > MAX_HASH:
                        update.message.reply_text(message_format(mess['error_exceed_hash']), parse_mode='MarkdownV2')
                        return
                    for item in input_hashes:
                        if not hash_validator(item):
                            update.message.reply_text(message_format(mess['error_invalid_hash']), parse_mode='MarkdownV2')
                            return
                # /hunt update <hunt_id> <md5, sha1, sha256>
                if arg_0 == "update":
                    update_hashes = list(set(arg_list[2:]))
                    if not hunt_id_validator(arg_list[1]):
                        update.message.reply_text(message_format(mess['error_invalid_hunt_id']), parse_mode='MarkdownV2')
                        return
                    if len(update_hashes) > MAX_HASH:
                        update.message.reply_text(message_format(mess['error_exceed_hash']), parse_mode='MarkdownV2')
                        return
                    for item in update_hashes:
                        if not hash_validator(item):
                            update.message.reply_text(message_format(mess['error_invalid_hash']), parse_mode='MarkdownV2')
                            return
                # /hunt stime <hunt_id> 23:10:01 12:15:04
                if arg_0 == "stime":
                    schedule_times = list(set(arg_list[2:]))
                    if not hunt_id_validator(arg_list[1]):
                        update.message.reply_text(message_format(mess['error_invalid_hunt_id']), parse_mode='MarkdownV2')
                        return
                    for item in schedule_times:
                        if not schedule_time_validator(item):
                            update.message.reply_text(message_format(mess['error_schedule_time']), parse_mode='MarkdownV2')
                            return
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return True


def hunting_handler(update, context):
    try:
        if not command_validator(update, context):
            return
        _, __, ___, vt_key = hunting_init(update, context)
        cmd = str(context.args[0])
        return {
            'hash': hunting_hash,
            'url': hunting_url,
            'update': hunting_update_hash,
            'si': hunting_search_intelligence,
            'stime': hunting_set_time,
            'dump': hunting_dump_job,
            'del': hunting_delete_job,
            'log': hunting_log_job,
            'start': hunting_start_schedule,
            'stop': hunting_stop_schedule,
            'status': hunting_status_schedule,
            'export': hunting_export_hashes
        }.get(cmd)(update, context, vt_key)
    except Exception as ex:
        logger.warning(str(ex))


def hunting_hash(update, context, vt_key):
    try:
        arg_list = context.args
        input_hashes = list(set(arg_list[1:]))
        chat_id = update.message.chat_id
        username = update.message.chat.username
        # Get pre content and extract it to get pre hashes
        pre_hashes = []
        pre_hunt_content = vt_hunting_get_hunt_content(hunt_chat_id=chat_id, is_hash=True, to_dict=True)
        if pre_hunt_content:
            for item in pre_hunt_content:
                data_dec, _ = data_decode(item.get('hunt_content'))
                pre_hashes.extend(data_dec.split(';'))
        # Get new unique hashes from user input
        unique_hashes = []
        for item in input_hashes:
            if item not in pre_hashes:
                unique_hashes.append(item)
        if not unique_hashes:
            mess_text = mess['error_add_job']
            mess_text += "\n - Số hashes bị trùng: %d" % len(input_hashes)
            update.message.reply_text(message_format(mess_text), parse_mode='MarkdownV2')
            return
        content = ";".join(unique_hashes)
        hunt_content, hunt_checksum = data_encode(content)
        time_stamp = int(datetime_to_unix(datetime.now()))
        job_item = {
            "hunt_id": time_stamp,
            "hunt_type": "hash",
            "hunt_create_time": time_stamp,
            "hunt_chat_id": chat_id,
            "hunt_username": username,
            "hunt_run_at": "",
            "hunt_content": hunt_content,
            "hunt_checksum": hunt_checksum,
            "hunt_source": "manual"
        }
        if vt_hunting_add_job(job_item):
            mess_text = mess['success_add_job']
            mess_text += "\n - Số hashes thêm mới: %d" % len(unique_hashes)
            mess_text += "\n - Số hashes bị trùng: %d" % (len(input_hashes) - len(unique_hashes))
            mess_text += "\n - HuntID: %d" % time_stamp
            update.message.reply_text(message_format(mess_text), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_add_job']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def hunting_url(update, context, vt_key):
    try:
        input_url = str(context.args[1])
        chat_id = update.message.chat_id
        username = update.message.chat.username
        # Get pre source and extract it to get pre url
        pre_urls = []
        pre_hunt_source = vt_hunting_get_hunt_content(hunt_chat_id=chat_id, is_url=True, to_dict=True)
        if pre_hunt_source:
            for item in pre_hunt_source:
                pre_urls.append(item.get('hunt_source'))
        if input_url in pre_urls:
            mess_text = mess['error_add_job']
            mess_text += "\n - URL đã tồn tại trước đó"
            update.message.reply_text(message_format(mess_text), parse_mode='MarkdownV2')
            return
        # Get new hashes from URL
        resp = requests.get(input_url)
        sleep(1)
        input_hashes = list(iocextract.extract_hashes(resp.text))
        content = ";".join(list(set(input_hashes)))
        hunt_content, hunt_checksum = data_encode(content)
        time_stamp = int(datetime_to_unix(datetime.now()))
        job_item = {
            "hunt_id": time_stamp,
            "hunt_type": "url",
            "hunt_create_time": time_stamp,
            "hunt_chat_id": chat_id,
            "hunt_username": username,
            "hunt_run_at": "",
            "hunt_content": hunt_content,
            "hunt_checksum": hunt_checksum,
            "hunt_source": input_url
        }
        if vt_hunting_add_job(job_item):
            mess_text = mess['success_add_job']
            mess_text += "\n - Số hashes thêm mới: %d" % len(set(input_hashes))
            mess_text += "\n - HuntID: %d" % time_stamp
            update.message.reply_text(message_format(mess_text), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_add_job']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def hunting_update_hash(update, context, vt_key):
    try:
        arg_list = context.args
        args_len = len(context.args)
        chat_id = update.message.chat_id
        job = {}
        input_hashes = []
        # Check Hunting Job by ID are exist?
        input_hunt_id = arg_list[1]
        hunting_jobs = vt_hunting_get_hunt_summary(hunt_chat_id=chat_id, hunt_id=input_hunt_id, to_dict=True)
        if not hunting_jobs:
            update.message.reply_text(message_format(mess['error_job_exist']), parse_mode='MarkdownV2')
            return

        # /hunt update <hunt_id>
        if args_len == 2:
            job = hunting_jobs[0]
            if job.get("hunt_type") != "url":
                update.message.reply_text(message_format(mess['error_job_type_url']), parse_mode='MarkdownV2')
                return
            # Get new hashes from hunt source
            hunt_source = job.get("hunt_source")
            resp = requests.get(hunt_source)
            sleep(1)
            input_hashes = list(iocextract.extract_hashes(resp.text))
            input_hashes = list(set(input_hashes))

        # /hunt update <hunt_id> <hashes>
        if args_len > 2:
            job = hunting_jobs[0]
            if job.get("hunt_type") != "hash":
                update.message.reply_text(message_format(mess['error_job_type_hash']), parse_mode='MarkdownV2')
                return
            # Get new hashes from user input
            input_hashes = list(set(arg_list[2:]))

        # Get pre content and extract it to get pre hashes
        pre_hashes = []
        data_dec, _ = data_decode(job.get("hunt_content"))
        pre_hashes.extend(data_dec.split(';'))
        pre_hashes = list(set(pre_hashes))
        new_hashes = []
        for item in input_hashes:
            if item not in pre_hashes:
                new_hashes.append(item)
        total_hashes = pre_hashes + new_hashes
        content = ";".join(total_hashes)
        hunt_content, hunt_checksum = data_encode(content)
        if vt_hunting_update_job(chat_id, input_hunt_id, hunt_content, hunt_checksum):
            mess_text = mess['success_job_update']
            mess_text += "\n - Số hashes trước đó: %d" % len(pre_hashes)
            mess_text += "\n - Số hashes thêm mới: %d" % len(new_hashes)
            update.message.reply_text(message_format(mess_text), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_job_update']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def hunting_search_intelligence(update, context, vt_key):
    try:
        arg_list = context.args
        chat_id = update.message.chat_id
        username = update.message.chat.username
        input_query = " ".join(arg_list[1:])
        # Get pre content and extract it to get pre query
        pre_query = []
        pre_hunt_content = vt_hunting_get_hunt_content(hunt_chat_id=chat_id, is_query=True, to_dict=True)
        if pre_hunt_content:
            for item in pre_hunt_content:
                data_dec, _ = data_decode(item.get('hunt_content'))
                pre_query.append(data_dec)
        # Check input query already exists?
        # crazy compare :| do not use it!!
        from collections import Counter
        compare_query = lambda x, y: Counter(x) == Counter(y)
        for query in pre_query:
            if compare_query(input_query, query):
                mess_text = mess['error_add_job']
                mess_text += "\n - Search Query đã tồn tại trước đó"
                update.message.reply_text(message_format(mess_text), parse_mode='MarkdownV2')
                return
        hunt_content, hunt_checksum = data_encode(input_query)
        time_stamp = int(datetime_to_unix(datetime.now()))
        job_item = {
            "hunt_id": time_stamp,
            "hunt_type": "query",
            "hunt_create_time": time_stamp,
            "hunt_chat_id": chat_id,
            "hunt_username": username,
            "hunt_run_at": "",
            "hunt_content": hunt_content,
            "hunt_checksum": hunt_checksum,
            "hunt_source": 'manual'
        }
        if vt_hunting_add_job(job_item):
            mess_text = mess['success_add_job']
            mess_text += "\n - Search Query: %s" % input_query
            mess_text += "\n - HuntID: %d" % time_stamp
            update.message.reply_text(message_format(mess_text), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_add_job']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def hunting_set_time(update, context, vt_key):
    try:
        arg_list = context.args
        chat_id = update.message.chat_id
        input_hunt_id = str(arg_list[1])
        input_schedule_times = list(set(arg_list[2:]))
        input_schedule_times = ";".join(input_schedule_times)
        # Checking exist hunting jon in db?
        hunting_jobs = vt_hunting_get_hunt_summary(hunt_chat_id=chat_id, hunt_id=input_hunt_id, to_dict=True)
        if not hunting_jobs:
            update.message.reply_text(message_format(mess['error_job_exist']), parse_mode='MarkdownV2')
            return
        # Set hunt_status and hunt_run_at (schedule times)
        if vt_hunting_set_time_job(chat_id, input_hunt_id, True, input_schedule_times):
            update.message.reply_text(message_format(mess['success_job_update']), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_job_update']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def hunting_dump_job(update, context, vt_key):
    try:
        args_len = len(context.args)
        chat_id = update.message.chat_id
        hunting_jobs = vt_hunting_get_hunt_summary(hunt_chat_id=chat_id, to_dict=True)
        if not hunting_jobs:
            update.message.reply_text(message_format(mess['error_empty_job']), parse_mode='MarkdownV2')
            return
        # /hunt dump
        if args_len == 1:
            batch_size = 5
            for i in range(0, len(hunting_jobs), batch_size):
                batch = hunting_jobs[i:i + batch_size]
                batch_data = []
                for job in batch:
                    hunt_content = ""
                    hunt_type = job.get("hunt_type")
                    data_dec, _ = data_decode(job.get("hunt_content"))
                    num_of_hashes = 0
                    if hunt_type == "hash" or hunt_type == "url":
                        hunt_content = "['...']"
                        num_of_hashes = len(data_dec.split(";"))
                    if hunt_type == "query":
                        hunt_content = data_dec
                    hunt_last_run = unix_to_datetime(float(job.get("hunt_last_run"))).strftime('%Y-%m-%d %H:%M:%S')
                    hunt_create_time = unix_to_datetime(float(job.get("hunt_create_time"))).strftime('%Y-%m-%d %H:%M:%S')
                    hunt_status = "ON" if job.get("hunt_status") == 1 else "OFF"
                    item = {
                        "id": job.get("hunt_id"),
                        "type": hunt_type,
                        "create_time": hunt_create_time,
                        "status": hunt_status,
                        "run_at": job.get("hunt_run_at"),
                        "num_of_hashes": num_of_hashes,
                        "content": hunt_content,
                        "source": job.get("hunt_source"),
                        "last_run": hunt_last_run
                    }
                    batch_data.append(item)
                batch_text = json.dumps(batch_data, sort_keys=False, indent=4)
                update.message.reply_text(message_format(batch_text), parse_mode='MarkdownV2')

        # /hunt dump [hunt_id]
        if args_len == 2:
            input_hunt_id = str(context.args[1])
            hunting_jobs_by_id = vt_hunting_get_hunt_summary(hunt_chat_id=chat_id, hunt_id=input_hunt_id, to_dict=True)
            if not hunting_jobs_by_id:
                update.message.reply_text(message_format(mess['error_job_exist']), parse_mode='MarkdownV2')
                return
            job = hunting_jobs_by_id[0]
            hunt_content = ""
            hunt_type = job.get("hunt_type")
            data_dec, _ = data_decode(job.get("hunt_content"))
            hashes = []
            num_of_hashes = 0
            is_hash_or_url = False
            if hunt_type == "hash" or hunt_type == "url":
                hashes = data_dec.split(";")
                hunt_content = hashes
                num_of_hashes = len(hashes)
                is_hash_or_url = True
            if hunt_type == "query":
                hunt_content = data_dec
            hunt_create_time = unix_to_datetime(float(job.get("hunt_create_time"))).strftime('%Y-%m-%d %H:%M:%S')
            hunt_last_run = unix_to_datetime(float(job.get("hunt_last_run"))).strftime('%Y-%m-%d %H:%M:%S')
            hunt_status = "ON" if job.get("hunt_status") == 1 else "OFF"
            item = {
                "id": job.get("hunt_id"),
                "type": hunt_type,
                "create_time": hunt_create_time,
                "status": hunt_status,
                "run_at": job.get("hunt_run_at"),
                "num_of_hashes": num_of_hashes,
                "content": hunt_content,
                "source": job.get("hunt_source"),
                "last_run": hunt_last_run
            }
            if len(hashes) > MAX_HASH and is_hash_or_url:
                data = json.dumps(item, sort_keys=False, indent=4).encode('utf-8')
                filename = str(chat_id) + '_' + str(input_hunt_id) + '.json'
                context.bot.send_document(chat_id=chat_id, document=data, filename=filename)
                return
            mess_text = json.dumps(item, sort_keys=False, indent=4)
            update.message.reply_text(message_format(mess_text), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def hunting_export_hashes(update, context, vt_key):
    try:
        hashes_monitor = []
        hashes_found = []
        chat_id = update.message.chat_id
        hunting_jobs = vt_hunting_get_hunt_summary(hunt_chat_id=chat_id, to_dict=True)
        if not hunting_jobs:
            update.message.reply_text(message_format(mess['error_empty_job']), parse_mode='MarkdownV2')
            return
        hunting_jobs_logs = vt_hunting_logs_get_summary(hunt_chat_id=chat_id, to_dict=True)

        # Get all hashes monitor
        for item in hunting_jobs:
            if item.get("hunt_type") == "query":
                continue
            data_dec, _ = data_decode(item.get("hunt_content"))
            hashes_monitor.extend(data_dec.split(";"))
        hashes_monitor = list(set(hashes_monitor))

        # Get all hash found
        for item in hunting_jobs_logs:
            data_dec, _ = data_decode(item.get("hunt_content"))
            hashes_found.extend(data_dec.split(";"))
        hashes_found = list(set(hashes_found))
        data_export = {
            "chat_id": chat_id,
            "num_of_hash_monitor": len(hashes_monitor),
            "hashes_monitor": hashes_monitor,
            "num_of_hash_found": len(hashes_found),
            "hashes_found": hashes_found
        }

        # Send result to User
        if len(hashes_monitor) > MAX_HASH_EXPORT or len(hashes_found) > MAX_HASH_EXPORT:
            data = json.dumps(data_export, sort_keys=False, indent=4).encode('utf-8')
            filename = str(chat_id) + '_hunt_export.json'
            context.bot.send_document(chat_id=chat_id, document=data, filename=filename)
            return
        mess_text = json.dumps(data_export, sort_keys=False, indent=4)
        update.message.reply_text(message_format(mess_text), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def hunting_delete_job(update, context, vt_key):
    try:
        args_len = len(context.args)
        chat_id = update.message.chat_id
        # /hunt del <hunt_id>
        if args_len == 2:
            input_hunt_id = str(context.args[1])
            hunting_jobs = vt_hunting_get_hunt_summary(hunt_chat_id=chat_id, hunt_id=input_hunt_id, to_dict=True)
            if not hunting_jobs:
                update.message.reply_text(message_format(mess['error_job_exist']), parse_mode='MarkdownV2')
                return
            if vt_hunting_del_job(hunt_chat_id=chat_id, hunt_id=input_hunt_id):
                update.message.reply_text(message_format(mess['success_del_job']), parse_mode='MarkdownV2')
            else:
                update.message.reply_text(message_format(mess['error_del_job']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def hunting_log_job(update, context, vt_key):
    try:
        chat_id = update.message.chat_id
        input_hunt_id = str(context.args[1])
        hunting_jobs_by_id = vt_hunting_logs_get_summary(hunt_chat_id=chat_id, hunt_id=input_hunt_id, to_dict=True)
        if not hunting_jobs_by_id:
            update.message.reply_text(message_format(mess['error_job_exist']), parse_mode='MarkdownV2')
            return
        job = hunting_jobs_by_id[0]
        data_dec, _ = data_decode(job.get("hunt_content"))
        hashes = data_dec.split(";")
        num_of_hashes = len(hashes)
        last_update = unix_to_datetime(float(job.get("hunt_last_update"))).strftime('%Y-%m-%d %H:%M:%S')
        item = {
            "id": job.get("hunt_id"),
            "type": "report",
            "chat_id": job.get("hunt_chat_id"),
            "num_of_hashes": num_of_hashes,
            "hashes": hashes,
            "last_update": last_update
        }
        if num_of_hashes > 64:
            data = json.dumps(item, sort_keys=False, indent=4).encode('utf-8')
            filename = str(chat_id) + '_' + str(input_hunt_id) + '.json'
            context.bot.send_document(chat_id=chat_id, document=data, filename=filename)
            return
        text = json.dumps(item, sort_keys=False, indent=4)
        update.message.reply_text(message_format(text), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def hunting_start_schedule(update, context, vt_key):
    try:
        chat_id = update.message.chat_id
        username = update.message.chat.username
        hunting_jobs = vt_hunting_get_hunt_summary(hunt_chat_id=chat_id, to_dict=True)
        if not hunting_jobs:
            update.message.reply_text(message_format(mess['error_empty_job']), parse_mode='MarkdownV2')
            return
        for job in hunting_jobs:
            if job.get("hunt_status") == 0:
                continue
            hunt_type = job.get("hunt_type")
            ctx_data = {
                "chat_id": chat_id,
                "username": username,
                "hunt_id": job.get("hunt_id"),
                "hunt_type": hunt_type,
                "vt_key": vt_key
            }
            job_name = str(job.get("hunt_id"))
            data_dec, _ = data_decode(job.get("hunt_content"))
            hunt_run_at = job.get("hunt_run_at").split(";")
            for rat in hunt_run_at:
                hours = int(rat.split(":")[0])
                minute = int(rat.split(":")[1])
                seconds = int(rat.split(":")[2])
                ts = time(hour=hours, minute=minute, second=seconds, tzinfo=pytz.timezone('Asia/Ho_Chi_Minh'))
                days = (0, 1, 2, 3, 4, 5, 6)
                if hunt_type == "hash" or hunt_type == "url":
                    ctx_data["hunt_content"] = data_dec.split(";")
                    context.job_queue.run_daily(hunting_hash_task, time=ts, days=days, context=ctx_data, name=job_name)
                elif job.get("hunt_type") == "query":
                    ctx_data["hunt_content"] = data_dec
                    context.job_queue.run_daily(hunting_query_task, time=ts, days=days, context=ctx_data, name=job_name)
                result_text = "Đã lập lịch Job %s chạy vào lúc %s" % (job_name, rat)
                update.message.reply_text(message_format(result_text), parse_mode='MarkdownV2')
        # Case 1: Run one
        # seconds = 3
        # context.job_queue.run_once(hunting_task, seconds, context=chat_id, name=str(chat_id))

        # Case 2: Run repeating
        # seconds = 5
        # context.job_queue.run_repeating(hunting_task, seconds, context=chat_id, name=str(chat_id))

        # Case 3: Run daily in specific time: 00:33:00
        # ts = time(hour=22, minute=39, second=00, tzinfo=pytz.timezone('Asia/Ho_Chi_Minh'))
        # days = (0, 1, 2, 3, 4, 5, 6)
        # context.job_queue.run_daily(hunting_task, time=ts, days=days, context=chat_id, name=str(chat_id))
    except Exception as ex:
        logger.warning(str(ex))


def hunting_hash_task(context):
    try:
        ctx_data = context.job.context
        chat_id = ctx_data.get("chat_id")
        username = ctx_data.get("username")
        hunt_id = ctx_data.get("hunt_id")
        vt_key = ctx_data.get("vt_key")
        hunt_type = ctx_data.get("hunt_type")
        input_hashes = ctx_data.get("hunt_content")

        # Get pre hashes from VTHuntingLogs
        pre_hashes = []
        pre_hunt_content = vt_hunting_logs_get_summary(hunt_chat_id=chat_id, hunt_id=hunt_id)
        if pre_hunt_content:
            data_dec, _ = data_decode(pre_hunt_content[0].get("hunt_content"))
            pre_hashes.extend(data_dec.split(";"))

        # Remove hashes if exist in pre_hashes
        unique_hashes = []
        for item in input_hashes:
            if item not in pre_hashes:
                unique_hashes.append(item)
        if not unique_hashes:
            return

        # Query unique hash in VirusTotal
        hashes_found = []
        vt_file = vtapi.VirusTotalAPIFiles(vt_key)
        for file_id in unique_hashes:
            try:
                result = vt_file.get_report(file_id)
                sleep(1)
            except Exception as ex:
                logger.warning(str(ex))
            else:
                if vt_file.get_last_http_error() == vt_file.HTTP_OK:
                    hashes_found.append(file_id)
        if not hashes_found:
            return

        # Update pre hashes and new hash to VTHuntingLogs
        total_hashes_found = list(set(pre_hashes + hashes_found))
        content = ";".join(total_hashes_found)
        hunt_content, hunt_checksum = data_encode(content)
        now_unix = int(datetime_to_unix(datetime.now()))
        set_content_result = vt_hunting_logs_set_content(chat_id, hunt_id, hunt_content, now_unix)

        # Update last run time to VTHunting
        last_run_result = vt_hunting_set_last_run(chat_id, hunt_id, now_unix)

        # Alert to user new hash found in VT
        text = {
            "id": hunt_id,
            "hunt_type": hunt_type,
            "message": "VT Hunting: Found some hashes on VT",
            "hashes": hashes_found
        }
        text = message_format(json.dumps(text, sort_keys=False, indent=4))
        context.bot.send_message(chat_id=chat_id, text=text, parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def hunting_query_task(context):
    try:
        ctx_data = context.job.context
        chat_id = ctx_data.get("chat_id")
        username = ctx_data.get("username")
        hunt_id = ctx_data.get("hunt_id")
        vt_key = ctx_data.get("vt_key")
        hunt_type = ctx_data.get("hunt_type")

        # VT Search Intelligence
        found_hashes = []
        try:
            si_limit = 20
            search_query = ctx_data.get("hunt_content")
            vt_etp = vtapi.VirusTotalAPIEnterprise(vt_key)
            vt_etp_result = vt_etp.intelligence_file_search(query=search_query, descriptors_only=False, limit=si_limit)
        except vtapi.VirusTotalAPIError as err:
            logger.warning(str(err) + " | " + str(err.err_code))
        else:
            if vt_etp.get_last_http_error() == vt_etp.HTTP_OK:
                tmp = json.loads(vt_etp_result)
                si_data = tmp.get("data")
                for item in si_data:
                    found_hashes.append(item.get("id"))
        if not found_hashes:
            return

        # Get pre hashes from VTHuntingLogs
        pre_hashes = []
        pre_hunt_content = vt_hunting_logs_get_summary(hunt_chat_id=chat_id, hunt_id=hunt_id)
        if pre_hunt_content:
            data_dec, _ = data_decode(pre_hunt_content[0].get("hunt_content"))
            pre_hashes.extend(data_dec.split(";"))

        # Remove hashes if exist in pre_hashes
        unique_hashes = []
        for item in found_hashes:
            if item not in pre_hashes:
                unique_hashes.append(item)
        if not unique_hashes:
            return

        # Update pre hashes and new unique hashes to db
        total_hashes_found = list(set(pre_hashes + unique_hashes))
        content = ";".join(total_hashes_found)
        hunt_content, hunt_checksum = data_encode(content)
        now_unix = int(datetime_to_unix(datetime.now()))
        set_content_result = vt_hunting_logs_set_content(chat_id, hunt_id, hunt_content, now_unix)

        # Update last run time to VTHunting
        last_run_result = vt_hunting_set_last_run(chat_id, hunt_id, now_unix)

        # Alert to user new hash found in VT
        text = {
            "id": hunt_id,
            "hunt_type": hunt_type,
            "message": "VT Hunting: Found some hashes on VT",
            "hashes": unique_hashes
        }
        text = message_format(json.dumps(text, sort_keys=False, indent=4))
        context.bot.send_message(chat_id=chat_id, text=text, parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def hunting_status_schedule(update, context, vt_key):
    try:
        chat_id = update.message.chat_id
        hunting_jobs = vt_hunting_get_hunt_summary(hunt_chat_id=chat_id, to_dict=True)
        if not hunting_jobs:
            update.message.reply_text(message_format(mess['error_empty_job']), parse_mode='MarkdownV2')
            return
        jobs_status = []
        for job in hunting_jobs:
            if job.get("hunt_status") == 0:
                continue
            job_name = str(job.get("hunt_id"))
            current_jobs = context.job_queue.get_jobs_by_name(job_name)
            item = {
                "id": job.get("hunt_id"),
                "type": job.get("hunt_type"),
                "source": job.get("hunt_source")
            }
            if not current_jobs:
                item["status"] = "exited"
            else:
                item["status"] = "running"
                item["number"] = len(current_jobs)
            jobs_status.append(item)
        if not jobs_status:
            update.message.reply_text(message_format(mess['error_empty_job_running']), parse_mode='MarkdownV2')
            return
        batch_size = 10
        for i in range(0, len(jobs_status), batch_size):
            batch = jobs_status[i:i + batch_size]
            batch_text = json.dumps(batch, sort_keys=False, indent=4)
            update.message.reply_text(message_format(batch_text), parse_mode='MarkdownV2')

    except Exception as ex:
        logger.warning(str(ex))


def hunting_stop_schedule(update, context, vt_key):
    try:
        chat_id = update.message.chat_id
        hunting_jobs = vt_hunting_get_hunt_summary(hunt_chat_id=chat_id, to_dict=True)
        if not hunting_jobs:
            update.message.reply_text(message_format(mess['error_empty_job']), parse_mode='MarkdownV2')
            return
        for job in hunting_jobs:
            if job.get("hunt_status") == 0:
                continue
            job_name = str(job.get("hunt_id"))
            job_removed = remove_job_if_exists(job_name, update, context)
        update.message.reply_text(message_format(mess['success_stop_job']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def remove_job_if_exists(name, update, context) -> bool:
    """Remove job with given name. Returns whether job was removed."""
    try:
        current_jobs = context.job_queue.get_jobs_by_name(name)
        if not current_jobs:
            return False
        for job in current_jobs:
            job.schedule_removal()
    except Exception as ex:
        logger.warning(str(ex))
    return True
