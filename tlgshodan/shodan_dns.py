import requests
from shodan import Shodan
from tlglogging.config import logger


def shodan_get_subdomain(key, domain, history=False):
    """
    Domain Information
    Get all the subdomains and other DNS entries for the given domain. Uses 1 query credit per lookup
    """
    try:
        sd = Shodan(key)
        resp = sd.dns.domain_info(domain=domain, history=history, type=None, page=1)
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return resp
    return None


def shodan_domain_to_ip(key, domains):
    """
    DNS Lookup
    Look up the IP address for the provided list of hostnames.
    """
    try:
        url = "https://api.shodan.io/dns/resolve?hostnames=" + ",".join(domains) + "&key=" + key
        resp = requests.get(url)
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return resp.content
    return None


def shodan_ip_to_domain(key, ips):
    """
    DNS Lookup
    Look up the IP address for the provided list of hostnames.
    """
    try:
        url = "https://api.shodan.io/dns/reverse?ips=" + ",".join(ips) + "&key=" + key
        resp = requests.get(url)
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return resp.content
    return None
