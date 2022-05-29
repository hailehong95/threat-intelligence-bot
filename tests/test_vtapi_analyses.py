#!/usr/bin/env python

import os
import json
import vtapi

from tests.test_vtapi_config import read_config, JSON_FILE
from tests.test_vtapi_config import write_config as write_report

TEST_DIR = os.path.dirname(os.path.realpath(__file__))
api_key = read_config(JSON_FILE)[0]['api_key']
vt = vtapi.VirusTotalAPIAnalyses(api_key)


def test_get_report(object_id):
    """
        - Phương thức 'get_report(object_id)' của lớp VirusTotalAPIAnalyses cho kết quả ngắn gọn
        - Phương thức 'get_report(file_id)' của lớp VirusTotalAPIFiles cho kết quả chi tiết
    """
    try:
        result = vt.get_report(object_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_analyses_test_get_report.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')
