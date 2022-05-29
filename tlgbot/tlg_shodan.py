import json
import time
import validators

from datetime import datetime
from tlgbot.tlg_sqlite import *
from tlgshodan.shodan_dns import *
from tlgshodan.shodan_search import *
from tlgshodan.shodan_utility import *
from tlglogging.config import logger
from tlgbot.tlg_banner import shodan_banner
from tlgbot.tlg_sqlite import sd_users_del_key
from tlgbot.tlg_sqlite import sd_users_search_key, sd_users_add_key
from tlgbot.tlg_utils import message_load, message_format, sd_key_validator


SD_ONE = ['del', 'info']
SD_TWO = ['add', 'info', 'ip', 'sub', 'dti', 'itd', 'search']
SD_MULTI = ['search', 'dti', 'itd']
SD_QUERY_LIMIT = 25
mess = message_load()['sd']


def sd_init(update, context):
    try:
        sd_key = ""
        is_available = False
        chat_id = update.message.chat_id
        user_key = sd_users_search_key(chat_id)
        if user_key:
            is_available = True
            sd_key = user_key[0].get("shodan_key")
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return is_available, sd_key


def command_validator(update, context):
    try:
        args_len = len(context.args)
        if args_len == 0:
            shodan_banner(update, context)
            return
        elif args_len == 1:
            arg_0 = str(context.args[0])
            if arg_0 == 'help':
                shodan_banner(update, context)
                return
            if arg_0 not in SD_ONE:
                update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                return
        elif args_len == 2:
            arg_0 = str(context.args[0])
            arg_1 = str(context.args[1])
            if arg_0 not in SD_TWO:
                update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                return
            else:
                if arg_0 == "add" or arg_0 == "info":
                    if not sd_key_validator(arg_1):
                        update.message.reply_text(message_format(mess['error_invalid_shodan_key']), parse_mode='MarkdownV2')
                        return
                if arg_0 == "ip" or arg_0 == "itd":
                    if not validators.ipv4(arg_1):
                        update.message.reply_text(message_format(mess['error_invalid_ipv4']), parse_mode='MarkdownV2')
                        return
                if arg_0 == "sub" or arg_0 == "dti":
                    if not validators.domain(arg_1):
                        update.message.reply_text(message_format(mess['error_invalid_domain']), parse_mode='MarkdownV2')
                        return
                if arg_0 == "search":
                    return True
        else:
            arg_list = context.args
            if arg_list[0] not in SD_MULTI:
                update.message.reply_text(message_format(mess['error_param']), parse_mode='MarkdownV2')
                return
            else:
                if arg_list[0] == 'dti':
                    if len(set(arg_list[1:])) > 10:
                        update.message.reply_text(message_format(mess['error_exceed_domains']), parse_mode='MarkdownV2')
                        return
                    for dm in set(arg_list[1:]):
                        if not validators.domain(dm):
                            update.message.reply_text(message_format(mess['error_invalid_domain']), parse_mode='MarkdownV2')
                            return
                elif arg_list[0] == 'itd':
                    if len(set(arg_list[1:])) > 10:
                        update.message.reply_text(message_format(mess['error_exceed_ips']), parse_mode='MarkdownV2')
                        return
                    for ip in set(arg_list[1:]):
                        if not validators.ipv4(ip):
                            update.message.reply_text(message_format(mess['error_invalid_ipv4']), parse_mode='MarkdownV2')
                            return
                elif arg_list[0] == 'search':
                    return True
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return True


def sd_handler(update, context):
    try:
        if not command_validator(update, context):
            return
        cmd = str(context.args[0])
        return {
            'add': sd_bot_add_key,
            'del': sd_bot_del_key,
            'info': sd_bot_info_key,
            'ip': sd_bot_search_ip,
            'search': sd_bot_query,
            'sub': sd_bot_sub_domain,
            'dti': sd_bot_domains_to_ips,
            'itd': sd_bot_ips_to_domains
        }.get(cmd)(update, context)
    except Exception as ex:
        logger.warning(str(ex))


def sd_bot_add_key(update, context):
    try:
        api_key = str(context.args[1])
        chat_id = update.message.chat_id
        username = update.message.chat.username
        user_key = sd_users_search_key(chat_id)
        if not user_key:
            is_valid, res = shodan_api_info(api_key)
            if not is_valid:
                update.message.reply_text(message_format(res), parse_mode='MarkdownV2')
                return
            # API Key is valid
            key_item = {
                "shodan_key": api_key,
                "chat_id": chat_id,
                "username": username
            }
            if sd_users_add_key(key_item):
                update.message.reply_text(message_format(mess['success_add_key']), parse_mode='MarkdownV2')
            else:
                update.message.reply_text(message_format(mess['error_add_key']), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_exist_key']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def sd_bot_del_key(update, context):
    try:
        is_available, sd_key = sd_init(update, context)
        if is_available:
            chat_id = update.message.chat_id
            if sd_users_del_key(chat_id):
                update.message.reply_text(message_format(mess['success_delete_key']), parse_mode='MarkdownV2')
            else:
                update.message.reply_text(message_format(mess['error_delete_key']), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_missing_key']), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def sd_bot_info_key(update, context):
    try:
        args_len = len(context.args)
        input_key = ""
        # /shodan info
        if args_len == 1:
            is_available, sd_key = sd_init(update, context)
            if not is_available:
                update.message.reply_text(message_format(mess['error_missing_key']), parse_mode='MarkdownV2')
                return
            input_key = sd_key
        # /shodan /info [key]
        elif args_len == 2:
            input_key = str(context.args[1])
        resp = shodan_api_info(input_key)
        resp = json.dumps(resp, sort_keys=False, indent=4)
        update.message.reply_text(message_format(resp), parse_mode='MarkdownV2')
    except Exception as ex:
        logger.warning(str(ex))


def sd_bot_search_ip(update, context):
    try:
        is_available, sd_key = sd_init(update, context)
        if is_available:
            ip_address = str(context.args[1])
            resp = shodan_search_ip(sd_key, ip_address)
            item = {
                "ip": resp["ip_str"],
                "hostnames": ", ".join(str(x) for x in resp.get("hostnames", "")),
                "vulns": ", ".join(str(x) for x in resp.get("vulns", "")),
                "domains": ", ".join(str(x) for x in resp.get("domains", "")),
                "os": resp["os"],
                "last_update": datetime.fromisoformat(resp["last_update"]).strftime('%Y-%m-%d %H:%M:%S'),
                "location": resp["city"] + ", " + resp["country_name"] + " (%s)" % resp["country_code"],
                "org": resp["org"],
                "isp": resp["isp"],
                "asn": resp["asn"],
                "ports": ", ".join(str(x) for x in resp["ports"])
            }
            ports_data = []
            ports_list = resp["data"]
            for x in ports_list:
                vulns_dict = x.get("vulns", "")
                temp_data = x.get("data", "")
                timestamp_data = x.get("timestamp", "")
                temp = {
                    "port": x.get("port", ""),
                    "product": x.get("product", ""),
                    "transport": x.get("transport", "")
                }
                if timestamp_data:
                    temp["timestamp"] = datetime.fromisoformat(timestamp_data).strftime('%Y-%m-%d %H:%M:%S')
                if vulns_dict:
                    temp["vulns"] = ", ".join(list(vulns_dict.keys()))
                if temp_data:
                    temp["data"] = temp_data[0:256]
                ports_data.append(temp)

            item["data"] = ports_data
            summary_data = json.dumps(item, sort_keys=False, indent=4, ensure_ascii=False)
            update.message.reply_text(message_format(summary_data), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_missing_key']), parse_mode='MarkdownV2')
            return
    except Exception as ex:
        logger.warning(str(ex))


def sd_bot_query(update, context):
    try:
        is_available, sd_key = sd_init(update, context)
        if is_available:
            args_len = len(context.args)
            arg_list = context.args
            sd_query = ""
            if args_len == 2:
                sd_query = str(arg_list[1])
            else:
                sd_query = " ".join(arg_list[1:])
            resp = shodan_search_query(key=sd_key, query=sd_query, limit=SD_QUERY_LIMIT)
            matches = resp.get("matches", "")
            total = resp.get("total", 0)
            if not matches:
                update.message.reply_text(message_format(mess['error_empty_result']), parse_mode='MarkdownV2')
                return
            item = {
                "total": total,
                "matches": len(matches)
            }
            item = json.dumps(item, sort_keys=False, indent=4, ensure_ascii=False)
            update.message.reply_text(message_format(item), parse_mode='MarkdownV2')
            batch_size = 5
            for i in range(0, len(matches), batch_size):
                batch = matches[i:i + batch_size]
                batch_data = []
                for x in batch:
                    vulns = x.get("vulns", "")
                    domains = x.get("domains", "")
                    data = x.get("data", "")
                    timestamp = x.get("timestamp", "")
                    hostnames = x.get("hostnames", "")
                    tmp = {
                        "ip_str": x.get("ip_str", ""),
                        "port": x.get("port", ""),
                        "product": x.get("product", ""),
                        "asn": x.get("asn", ""),
                        "org": x.get("org", ""),
                        "isp": x.get("isp", ""),
                        "os": x.get("os", ""),
                        "transport": x.get("transport", ""),
                    }
                    if vulns:
                        tmp["vulns"] = ", ".join(list(vulns.keys()))
                    if domains:
                        tmp["domains"] = ", ".join(str(x) for x in domains)
                    if data:
                        tmp["data"] = data[0:256]
                    if timestamp:
                        tmp["timestamp"] = datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    if hostnames:
                        tmp["hostnames"] = ", ".join(str(x) for x in hostnames)
                    batch_data.append(tmp)
                batch_text = json.dumps(batch_data, sort_keys=False, indent=4)
                update.message.reply_text(message_format(batch_text), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_missing_key']), parse_mode='MarkdownV2')
            return
    except Exception as ex:
        logger.warning(str(ex))


def sd_bot_sub_domain(update, context):
    try:
        is_available, sd_key = sd_init(update, context)
        if is_available:
            domain = str(context.args[1])
            resp = shodan_get_subdomain(sd_key, domain, history=True)
            subdomain_list = []
            sub_list = resp.get("subdomains", "")
            if sub_list:
                for sub in sub_list:
                    subdomain_list.append(sub + "." + domain)
            mess_data = {
                "total": len(sub_list),
                "subdomains": subdomain_list
            }
            mess_data = json.dumps(mess_data, sort_keys=False, indent=4, ensure_ascii=False)
            if len(mess_data) > 4096:
                for x in range(0, len(mess_data), 4096):
                    update.message.reply_text(message_format(mess_data[x:x+4096]), parse_mode='MarkdownV2')
            else:
                update.message.reply_text(message_format(mess_data), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_missing_key']), parse_mode='MarkdownV2')
            return
    except Exception as ex:
        logger.warning(str(ex))


def sd_bot_domains_to_ips(update, context):
    try:
        is_available, sd_key = sd_init(update, context)
        if is_available:
            arg_list = context.args
            domain_list = list(set(arg_list[1:]))
            resp = shodan_domain_to_ip(sd_key, domain_list)
            time.sleep(1)
            if resp:
                resp = json.loads(resp)
                resp = json.dumps(resp, sort_keys=False, indent=4, ensure_ascii=False)
                update.message.reply_text(message_format(resp), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_missing_key']), parse_mode='MarkdownV2')
            return
    except Exception as ex:
        logger.warning(str(ex))


def sd_bot_ips_to_domains(update, context):
    try:
        is_available, sd_key = sd_init(update, context)
        if is_available:
            arg_list = context.args
            ip_address_list = list(set(arg_list[1:]))
            resp = shodan_ip_to_domain(sd_key, ip_address_list)
            if resp:
                resp = json.loads(resp)
                resp = json.dumps(resp, sort_keys=False, indent=4, ensure_ascii=False)
                update.message.reply_text(message_format(resp), parse_mode='MarkdownV2')
        else:
            update.message.reply_text(message_format(mess['error_missing_key']), parse_mode='MarkdownV2')
            return
    except Exception as ex:
        logger.warning(str(ex))
