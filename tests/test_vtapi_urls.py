#!/usr/bin/env python

import os
import json
import vtapi

from tests.test_vtapi_config import read_config, JSON_FILE
from tests.test_vtapi_config import write_config as write_report

api_key = read_config(JSON_FILE)[0]['api_key']
vt = vtapi.VirusTotalAPIUrls(api_key)
vt_analyses = vtapi.VirusTotalAPIAnalyses(api_key)

TEST_DIR = os.path.dirname(os.path.realpath(__file__))


def test_get_url_id_base64():
    url = 'https://www.google.com/'
    print(vt.get_url_id_base64(url))


def test_get_url_id_sha256():
    url = 'https://github.com/'
    print(vt.get_url_id_sha256(url))


def test_upload():
    """
     - Submmit một URL lên VT thông qua phương thức POST
     - Tương tự: analyse(url_id)
     - Trả về một url id
    """
    try:
        url = 'https://www.google.com/'
        result = vt.upload(url)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_urls_test_upload.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_report():
    """
     - Lấy VT Report về một domain. Domain truyền vào là một chuỗi url id.
     - Chuỗi url id theo định dạng của method get_url_id_sha256 hoặc get_url_id_base64 trả về
    """
    try:
        url_id = vt.get_url_id_base64('https://www.google.com/')
        result = vt.get_report(url_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_urls_test_get_report.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_reanalyse():
    """
     - Submmit một URL lên VT để Re-analyse
     - Tương tự: upload(url)
     - Trả về một url id
    """
    try:
        url_id = vt.get_url_id_base64('https://www.google.com/')
        result = vt.analyse(url_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_urls_test_reanalyse.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_comments():
    try:
        url_id = vt.get_url_id_base64('https://www.google.com/')
        result = vt.get_comments(url_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_urls_test_get_comments.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_put_comments():
    try:
        url_id = vt.get_url_id_base64('https://www.google.com/')
        text = 'is Safe.'
        result = vt.put_comments(url_id, text)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_urls_test_put_comments.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_votes():
    try:
        url_id = vt.get_url_id_base64('https://www.google.com/')
        result = vt.get_votes(url_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_urls_test_get_votes.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_put_votes():
    try:
        url_id = vt.get_url_id_base64('https://www.google.com/')
        result = vt.put_votes(url_id, False)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_urls_test_put_votes.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_relationship():
    # Tham khảo các relationship: https://developers.virustotal.com/v3.0/reference#url-object -> Relationships (table)
    try:
        url_id = vt.get_url_id_base64('https://www.google.com/')
        relationship = 'last_serving_ip_address'
        result = vt.get_relationship(url_id, relationship)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_urls_test_get_relationship_last_serving_ip_address.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_analyse_object_report():
    """
     - Lấy VT report cho các API: upload(url), analyse(url_id) bên trên
     - Các APT này chỉ trả về một object id
    """
    try:
        upload_result = 'u-d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86-1625064645'
        reanalyse_result = 'u-d0e196a0c25d35dd0a84593cbae0f38333aa58529936444ea26453eab28dfc86-1625066518'
        result = vt.get_analyse_object_report(upload_result)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_urls_test_get_analyse_object_report_upload_result.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')
