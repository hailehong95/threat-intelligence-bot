#!/usr/bin/env python

import os
import json
import vtapi

from tests.test_vtapi_config import read_config, JSON_FILE
from tests.test_vtapi_config import write_config as write_report

api_key = read_config(JSON_FILE)[0]['api_key']
vt = vtapi.VirusTotalAPIComments(api_key)

TEST_DIR = os.path.dirname(os.path.realpath(__file__))


def test_get_comments():
    """
     - Get những comment gần nhất từ VT
     - Cần limit số comment muốn lấy
    """
    try:
        result = vt.get_comments(limit=10)
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


def test_delete_comments():
    """
    - Xóa một comment theo id
    - Lấy comment_id bằng các phương thức 'get_comments' của các lớp: domain, ip, url,.v.v..
    """
    try:
        comment_id = ''
        result = vt.delete_comments(comment_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_urls_test_delete_comments.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')
