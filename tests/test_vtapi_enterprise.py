#!/usr/bin/env python

import os
import json
import vtapi

from tests.test_vtapi_config import read_config, JSON_FILE
from tests.test_vtapi_config import write_config as write_report

api_key = read_config(JSON_FILE)[2]['api_key']
vt = vtapi.VirusTotalAPIEnterprise(api_key)

TEST_DIR = os.path.dirname(os.path.realpath(__file__))
file_path = os.path.join(TEST_DIR, 'notepad.exe')
larger_file_path = os.path.join(TEST_DIR, 'SysinternalsSuite.zip')


def test_get_download_url():
    """
     - Trả về url cho phép download mẫu trên VT. Cần có VT Private API Key
     - URL này ko giới hạn số lần download, có thể share cho người khác download.
     - URL hết hạn sau 1h. Chỉ bị trừ 1 lần download trong quota, trong 1h download bao nhiêu cũng được.
    """
    try:
        file_id = 'a1dfbac053d9f93dc80792388d210a13b2f9fb69c15dacbf59e9043ea4e8afaf'
        result = vt.get_download_url(file_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_enterprise_test_get_download_url.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_download():
    """
     - Tương tự như method get_download_url nhưng method này sẽ chuyển hướng đến trang download luôn
    """
    try:
        file_id = 'a1dfbac053d9f93dc80792388d210a13b2f9fb69c15dacbf59e9043ea4e8afaf'
        result = vt.get_download(file_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            file_name = os.path.join(TEST_DIR, 'result', file_id)
            result = vt.save_download_file(result, file_name)
            print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_user():
    """
    - GET thông tin về một API Key hiện tại (Quota)
    - Cần phải có UserID hoặc API Key muốn kiểm tra
    """
    try:
        # user_id = 'cuckoosandbox'
        user_id = api_key
        result = vt.get_user(user_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_enterprise_test_get_user.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_api_usage():
    """
    - Thống kê chi tiết về mức độ sử dụng api key trong 30 ngày gần nhất
    - Ví dụ: key này đã get report bao lần, comment bao lần,.v.v..
    """
    try:
        # user_id = 'cuckoosandbox'
        user_id = api_key
        result = vt.get_api_usage(user_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_enterprise_test_get_api_usage.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_overall_quotas():
    """
    - Lấy thông tin quota tổng thể của một api key
    - Không bao gồm thông tin về user sở hữu api key đó
    """
    try:
        # user_id = 'cuckoosandbox'
        user_id = api_key
        result = vt.get_overall_quotas(user_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_enterprise_test_get_overall_quotas.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_intelligence_file_search():
    """
    - Tìm kiếm nâng cao dựa theo các đặc trưng của một đối tương (tệp tin)
    - Tham khảo 1: https://support.virustotal.com/hc/en-us/articles/360001387057-VirusTotal-Intelligence-Introduction
    - Tham khảo 2: https://support.virustotal.com/hc/en-us/articles/360001385897-VT-Intelligence-search-modifiers
    - Bổ sung: Tính năng intelligence search không chỉ áp dụng cho đối tượng tệp tin mà còn cho cả: domain, ip, url
    """
    try:
        # Với descriptors_only=True sẽ chỉ trả về hash của các tệp
        # query = 'type:doc tag:cve-2017-11882'
        # query = 'type:doc AND (tag:cve-2017-11882 OR tag:cve-2018-0802)'
        # query = 'type:pdf tag:exploit'
        # query = 'type:pdf tag:autoaction tag:js-embedded'
        # query = 'type:peexe size:150MB+ tag:signed metadata:"Hex-Rays SA"'
        query = 'name:cobaltstrike'
        # query = 'type:peexe size:150MB+ content:{4865782d52617973205341}'
        result = vt.intelligence_file_search(query=query, descriptors_only=False, limit=10)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_enterprise_test_intelligence_cobaltstrike.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_intelligence_zip_files():
    """
    - Gửi yêu cầu tạo một tệp ZIP chứa nhiều tệp bên trong. Được nén với 1 Password
    - Trả về zip_id của tệp, dùng trong việc kiểm tra thông tin về trạng thái tệp zip đã tạo sau này.
    """
    try:
        zip_password = 'not-infected'
        hashes = ['ffdc2353d38a6d2c8c659cc1367ad360345b309d', '57f60ca25a39ec93100b9007e0bac828d5c3dd62', '846159157dc7f0d9c83cddf43055b89108fc511f', '482681f75180bbb1286e1f93ce44dfae0b6b0007']
        # result = vt.intelligence_zip_files(hashes=hashes)
        result = vt.intelligence_zip_files(zip_password, hashes)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_enterprise_test_intelligence_zip_files.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_intelligence_zip_info():
    """
    - Check trạng thái của một tệp zip đã yêu cầu tạo trên VT
    - Trạng thái trả về là 'finished' thì tệp zip đc tạo thành công
    """
    try:
        zip_id = '4994144149864448'
        result = vt.intelligence_zip_info(zip_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_enterprise_test_intelligence_zip_info.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')
