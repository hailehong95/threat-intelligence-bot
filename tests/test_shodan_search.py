import os
import json

from tlgshodan.shodan_dns import *
from tlgshodan.shodan_search import *
from tlgshodan.shodan_utility import *
from tlgshodan.shodan_config import SHODAN_API as sd_key
from tests.test_vtapi_config import write_config as write_report

TEST_DIR = os.path.dirname(os.path.realpath(__file__))


def test_shodan_search_ip():
    # ip_address = "222.255.27.180"
    # ip_address = "183.81.34.136"
    # ip_address = "142.47.222.135"
    ip_address = "103.148.57.35"
    resp = shodan_search_ip(sd_key, ip_address)
    write_report(os.path.join(TEST_DIR, 'result', 'test_shodan_search_ip_103.148.57.35.json'), resp)


def test_shodan_count_result():
    query = 'port:22 country:"VN"'
    resp = shodan_count_result(sd_key, query)
    write_report(os.path.join(TEST_DIR, 'result', 'test_shodan_count_result.json'), resp)


def test_shodan_search_query():
    """
    Tham khảo:
    - query: https://beta.shodan.io/search/filters
    - facets: https://beta.shodan.io/search/facet
    - Theo mặc định trả về 100 kết quả trong dict data
    """
    # query = "product:nginx"
    # facets = "country,org"
    # query = "vuln:CVE-2019-19781 country:VN"
    query = "product:Apache"
    resp = shodan_search_query(key=sd_key, query=query)
    write_report(os.path.join(TEST_DIR, 'result', 'test_shodan_search_query_Apache.json'), resp)


def test_shodan_list_facets():
    resp = shodan_list_facets(sd_key)
    write_report(os.path.join(TEST_DIR, 'result', 'test_shodan_list_facets.json'), resp)


def test_shodan_list_filters():
    resp = shodan_list_filters(sd_key)
    write_report(os.path.join(TEST_DIR, 'result', 'test_shodan_list_filters.json'), resp)


def test_shodan_search_token():
    query = "Raspbian port:22"
    resp = shodan_search_token(sd_key, query)
    write_report(os.path.join(TEST_DIR, 'result', 'test_shodan_search_token.json'), resp)


def test_shodan_account_profile():
    key = "YOUR-SHODAN-API-KEY"
    resp = shodan_account_profile(key)
    resp = json.loads(resp)
    write_report(os.path.join(TEST_DIR, 'result', 'test_shodan_account_profile.json'), resp)


def test_shodan_get_subdomain():
    domain = "vnexpress.net"
    history = True
    resp = shodan_get_subdomain(sd_key, domain, history)
    write_report(os.path.join(TEST_DIR, 'result', 'test_shodan_get_subdomain.json'), resp)


def test_shodan_domain_to_ip():
    domains = ['dantri.com.vn', 'tuoitre.vn', 'facebook.com']
    resp = shodan_domain_to_ip(sd_key, domains)
    resp = json.loads(resp)
    write_report(os.path.join(TEST_DIR, 'result', 'test_shodan_domain_to_ip.json'), resp)


def test_shodan_ip_to_domain():
    ips = ["222.255.239.80", "183.81.34.136", "157.240.241.35"]
    resp = shodan_ip_to_domain(sd_key, ips)
    resp = json.loads(resp)
    write_report(os.path.join(TEST_DIR, 'result', 'test_shodan_ip_to_domain.json'), resp)


def test_shodan_api_info():
    is_valid, resp = shodan_api_info(sd_key)
    if is_valid:
        write_report(os.path.join(TEST_DIR, 'result', 'test_shodan_api_info.json'), resp)
