import json
import time
import vtapi
import validators

from tlglogging.config import logger
from tlgbot.tlg_banner import enterprise_banner
from tlgbot.tlg_sqlite import vt_users_get_enabled_key
from tlgbot.tlg_utils import expire_url_parsing, bytes2human
from tlgbot.tlg_utils import message_load, message_format, unix_to_datetime
from tlgbot.tlg_utils import hash_validator, zip_id_validator, vt_key_validator


ETP_ONE = ['info']
ETP_TWO = ['dl', 'szip', 'dzip', 'info', 'si']
ETP_MULTI = ['si', 'czip', 'dl']
SI_LIMIT = 20
mess = message_load()['enterprise']


def enterprise_init(update, context):
    try:
        vt_key = ""
        is_enable = is_private = False
        chat_id = update.message.chat_id
        user_key = vt_users_get_enabled_key(chat_id)
        if user_key:
            is_enable = True
            if user_key.get("is_private") == 1:
                is_private = True
                vt_key = user_key.get("api_key")
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return is_enable, is_private, vt_key


def command_validator(update, context):
    try:
        is_enable, is_private, vt_key = enterprise_init(update, context)
        if not is_enable:
            update.message.reply_text(message_format(mess['error_enable_key']), parse_mode='MarkdownV2')
            return
        if not is_private:
            update.message.reply_text(message_format(mess['error_permission_key']), parse_mode='MarkdownV2')
            return
        args_len = len(context.args)
        if args_len == 0:
            enterprise_banner(update, context)
            return
        elif args_len == 1:
            arg_0 = str(context.args[0])
            # /etp help
            if arg_0 == 'help':
                enterprise_banner(update, context)
                return
            if arg_0 not in ETP_ONE:
                update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                return
        elif args_len == 2:
            arg_0 = str(context.args[0])
            arg_1 = str(context.args[1])
            if arg_0 not in ETP_TWO:
                update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                return
            else:
                # /etp szip/dzip <zip_id>
                if arg_0 == 'szip' or arg_0 == 'dzip':
                    if not zip_id_validator(arg_1):
                        update.message.reply_text(message_format(mess['error_invalid_zip_id']), parse_mode='MarkdownV2')
                        return
                # /etp info [key]
                elif arg_0 == 'info':
                    if not vt_key_validator(arg_1):
                        update.message.reply_text(message_format(mess['error_vt_key']), parse_mode='MarkdownV2')
                        return
                # /etp dl <hash/url>
                elif arg_0 == 'dl':
                    if (not hash_validator(arg_1)) and (not validators.url(arg_1)):
                        update.message.reply_text(message_format(mess['error_invalid_hash_url']), parse_mode='MarkdownV2')
                        return
                # /etp si <query>
                elif arg_0 == 'si':
                    return True
                # /etp czip <zip_id>
                elif arg_0 == "czip":
                    if not hash_validator(arg_1):
                        update.message.reply_text(message_format(mess['error_invalid_hash']), parse_mode='MarkdownV2')
                        return
        else:
            arg_list = context.args
            if arg_list[0] not in ETP_MULTI:
                update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                return
            else:
                # /etp si <query>
                if arg_list[0] == 'si':
                    return True
                # /etp dl <hash/url>
                elif arg_list[0] == 'dl':
                    if len(set(arg_list[1:])) > 10:
                        update.message.reply_text(message_format(mess['error_exceed_hash_url']), parse_mode='MarkdownV2')
                        return
                    for x in set(arg_list[1:]):
                        if (not hash_validator(x)) and (not validators.url(x)):
                            update.message.reply_text(message_format(mess['error_invalid_hash_url']), parse_mode='MarkdownV2')
                            return
                # /etp czip <zip_id>
                elif arg_list[0] == "czip":
                    if len(set(arg_list[1:])) > 10:
                        update.message.reply_text(message_format(mess['error_exceed_hash_url']), parse_mode='MarkdownV2')
                        return
                    for x in arg_list[1:]:
                        if not hash_validator(x):
                            update.message.reply_text(message_format(mess['error_invalid_hash']), parse_mode='MarkdownV2')
                            return False
    except Exception as ex:
        logger.warning(str(ex))
    return True


def enterprise_handler(update, context):
    try:
        if not command_validator(update, context):
            return
        _, __, vt_key = enterprise_init(update, context)
        cmd = str(context.args[0])
        return {
            'info': etp_info,
            'si': etp_search_intelligence,
            'dl': etp_download_file,
            'czip': etp_create_zip,
            'szip': etp_status_zip,
            'dzip': etp_download_zip
        }.get(cmd)(update, context, vt_key)
    except Exception as ex:
        logger.warning(str(ex))


def etp_info(update, context, vt_key):
    """ Handler for: /etp info [key] """
    try:
        args_len = len(context.args)
        input_key = ""
        if args_len == 1:
            input_key = vt_key
        elif args_len == 2:
            input_key = str(context.args[1])
        vt_etp = vtapi.VirusTotalAPIEnterprise(input_key)
        result = vt_etp.get_user(input_key)
    except vtapi.VirusTotalAPIError as err:
        logger.warning(str(err) + " | " + str(err.err_code))
    else:
        if vt_etp.get_last_http_error() == vt_etp.HTTP_OK:
            result = json.loads(result)['data']['attributes']
            privileges = []
            quotas = {}
            for k, v in result['privileges'].items():
                if v['granted']:
                    privileges.append(k)
            for k, v in result['quotas'].items():
                if v['allowed'] > 0:
                    quotas[k] = "{}/{}".format(v['used'], v['allowed'])
            markdown_text = {
                'status': result['status'],
                'first_name': result['first_name'],
                'last_name': result['last_name'],
                'email': result['email'],
                'last_login': unix_to_datetime(float(result['last_login'])).strftime('%Y-%m-%d %H:%M:%S'),
                'user_since': unix_to_datetime(float(result['user_since'])).strftime('%Y-%m-%d %H:%M:%S'),
                'privileges': privileges,
                'quotas': quotas
            }
            mess_text = json.dumps(markdown_text, sort_keys=False, indent=4)
            update.message.reply_text(message_format(mess_text), parse_mode='MarkdownV2')
        else:
            logger.warning('HTTP Error [' + str(vt_etp.get_last_http_error()) + ']')


def etp_download_file(update, context, vt_key):
    """ Handler for: /etp dl <hashes/urls> """
    try:
        arg_list = context.args
        input_hashes = []
        # Get all unique hash from user input
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
        # Get sample from VT
        vt_samples_link = []
        vt_etp = vtapi.VirusTotalAPIEnterprise(vt_key)
        for file_id in input_hashes:
            try:
                resp = vt_etp.get_download_url(file_id)
            except Exception as ex:
                logger.warning('get_download_url - ' + str(ex))
            else:
                resp = json.loads(resp)
                if vt_etp.get_last_http_error() == vt_etp.HTTP_OK:
                    item = {
                        "hash": file_id,
                        "download": "<a href='%s'>link</a>" % resp.get("data"),
                        "expires_on": expire_url_parsing(resp.get("data"))
                    }
                    vt_samples_link.append(item)
                else:
                    item = {
                        "hash": file_id,
                        "download": resp["error"].get("code")
                    }
                    vt_samples_link.append(item)
        if not vt_samples_link:
            update.message.reply_text(message_format(mess['error_empty_result']), parse_mode='MarkdownV2')
            return
        # Send message to user
        batch_size = 2
        for i in range(0, len(vt_samples_link), batch_size):
            batch = vt_samples_link[i:i + batch_size]
            batch_text = json.dumps(batch, sort_keys=False, indent=4)
            update.message.reply_text(batch_text, parse_mode='HTML')
    except Exception as ex:
        logger.warning(str(ex))


def etp_search_intelligence(update, context, vt_key):
    """ Handler for: /etp si <query> """
    try:
        arg_list = context.args
        input_query = " ".join(arg_list[1:])
        try:
            vt_etp = vtapi.VirusTotalAPIEnterprise(vt_key)
            result = vt_etp.intelligence_file_search(query=input_query, descriptors_only=False, limit=SI_LIMIT)
        except vtapi.VirusTotalAPIError as err:
            logger.warning('intelligence_file_search - ' + str(err) + " | " + str(err.err_code))
        else:
            if vt_etp.get_last_http_error() == vt_etp.HTTP_OK:
                tmp = json.loads(result)
                si_data = tmp.get("data")
                # Check intelligence data exist
                if not si_data:
                    update.message.reply_text(message_format(mess['error_empty_result']), parse_mode='MarkdownV2')
                    return
                # Send message to user
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
            else:
                response = vt_etp.get_last_result()
                markdown_text = json.loads(response)
                update.message.reply_text(message_format(markdown_text), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def etp_create_zip(update, context, vt_key):
    """ Handler for: /etp czip <hash1 hash2> """
    try:
        vt_etp = vtapi.VirusTotalAPIEnterprise(vt_key)
    except Exception as ex:
        logger.warning(str(ex))


def etp_status_zip(update, context, vt_key):
    """ Handler for: /etp szip <zip_id> """
    try:
        vt_etp = vtapi.VirusTotalAPIEnterprise(vt_key)
    except Exception as ex:
        logger.warning(str(ex))


def etp_download_zip(update, context, vt_key):
    """ Handler for: /etp dzip <zip_id> """
    try:
        vt_etp = vtapi.VirusTotalAPIEnterprise(vt_key)
    except Exception as ex:
        logger.warning(str(ex))
