import requests
import ipaddress
from shodan import Shodan
from tlglogging.config import logger


def ip_to_int(ip_address: str):
    return int(ipaddress.IPv4Address(ip_address))


def int_to_ip(number: int):
    return str(ipaddress.IPv4Address(number))


def shodan_account_profile(key):
    """
    Account Profile
    Returns information about the Shodan account linked to this API key
    """
    try:
        url = "https://api.shodan.io/account/profile?key=" + key
        resp = requests.get(url)
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return resp.content
    return None


def shodan_api_info(key):
    """
    API Plan Information
    Returns information about the API plan belonging to the given API key
    """
    try:
        sd = Shodan(key)
        resp = sd.info()
    except Exception as ex:
        logger.warning(str(ex))
        return False, str(ex)
    else:
        return True, resp
