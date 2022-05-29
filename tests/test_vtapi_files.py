#!/usr/bin/env python

import os
import json
import vtapi

from tests.test_vtapi_config import read_config, JSON_FILE
from tests.test_vtapi_config import write_config as write_report

api_key = read_config(JSON_FILE)[0]['api_key']
vt = vtapi.VirusTotalAPIFiles(api_key)

TEST_DIR = os.path.dirname(os.path.realpath(__file__))
file_path = os.path.join(TEST_DIR, 'notepad.exe')
larger_file_path = os.path.join(TEST_DIR, 'SysinternalsSuite.zip')


def test_get_file_id():
    # Tính MD5, SHA1, SHA256 của một tệp tin
    file_id = vt.get_file_id(file_path)
    print(file_id)


def test_upload():
    # Upload một tệp tin lên VT, trả về một analysis identifier (str)
    # Sử dụng phương thức 'get_report(object_id)' của lớp VirusTotalAPIAnalyses để lấy kết quả phân tích từ VT
    try:
        result = vt.upload(file_path)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            return result
            # result = json.loads(result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_upload_larger_file():
    try:
        upload_url = vt.get_upload_url()
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            upload_url = json.loads(upload_url)['data']
            try:
                result = vt.upload_larger_file(larger_file_path, upload_url)
            except vtapi.VirusTotalAPIError as err:
                print(err, err.err_code)
            else:
                if vt.get_last_http_error() == vt.HTTP_OK:
                    return result
                    # result = json.loads(result)
                    # result = json.dumps(result, sort_keys=False, indent=4)
                    # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_report():
    """
        - Lấy kết quả phân tích từ VT thông qua mã băm một tệp tin: md5, sha1, sha256
        - Phương thức 'get_report(object_id)' của lớp VirusTotalAPIAnalyses cho kết quả ngắn gọn
        - Phương thức 'get_report(file_id)' của lớp VirusTotalAPIFiles cho kết quả chi tiết
    """
    try:
        file_id = 'b9d410d973dbb040a8a7bb23898ed92c205d7e1d249bfdb0965239b97b5cffdf'
        result = vt.get_report(file_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_get_report_by_hash_C_037.NLS.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_reanalyse():
    # Trả về một analysis identifier (str)
    # Sử dụng phương thức 'get_report(object_id)' của lớp VirusTotalAPIAnalyses để lấy kết quả phân tích từ VT
    try:
        file_id = '729f12b7ca02aa43785645aa14c72f414d6336a13d14ed190d634b5724d00a08'
        object_id = vt.analyse(file_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            return object_id
            # object_id = json.loads(object_id)['data']['id']
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_comments():
    try:
        file_id = '729f12b7ca02aa43785645aa14c72f414d6336a13d14ed190d634b5724d00a08'
        result = vt.get_comments(file_id, 5)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_get_comments.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_put_comments():
    try:
        file_id = 'a1dfbac053d9f93dc80792388d210a13b2f9fb69c15dacbf59e9043ea4e8afaf'
        text = 'is Safe'
        result = vt.put_comments(file_id, text)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_put_comments.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_votes():
    try:
        file_id = '729f12b7ca02aa43785645aa14c72f414d6336a13d14ed190d634b5724d00a08'
        result = vt.get_votes(file_id, 5)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_get_votes.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_put_votes():
    try:
        file_id = 'a1dfbac053d9f93dc80792388d210a13b2f9fb69c15dacbf59e9043ea4e8afaf'
        result = vt.put_votes(file_id, False)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_put_votes.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_relationship():
    """
        - Get relationship của một file:
            + bundled_files: các tệp chứa bên trong một tệp nén. vd: zip
            + behaviours: Dựa vào kết quả phân tích của các sandbox. Là các hành vi của tệp khi chạy.
    """
    try:
        # SysinternalsSuite.zip
        # file_id = '90d547d061ef448eb5063ddf0e8e5eab67ee1c5fe6fd9ade53a58e3a75ed6cc1'
        # relationship = 'bundled_files'
        # result = vt.get_relationship(file_id, relationship)

        # 49u6skNE.exe
        file_id = '729f12b7ca02aa43785645aa14c72f414d6336a13d14ed190d634b5724d00a08'
        relationship = 'behaviours'
        result = vt.get_relationship(file_id, relationship)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_get_relationship_behaviours.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_relationship_id():
    """
    - Không trả về chi tiết như get_relationship
    - Trả về thông tin ngắn gọn, là id của các relationship
    - VD:
        + Với relationship là contacted_domains => trả về các domain
        + Với relationship behaviours trả về các sandbox_id
    """
    try:
        file_id = '729f12b7ca02aa43785645aa14c72f414d6336a13d14ed190d634b5724d00a08'
        # relationship = 'contacted_domains'
        relationship = 'behaviours'
        result = vt.get_relationship_id(file_id, relationship)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_get_relationship_id_behaviours.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_behaviour_summary():
    """
        - Trả về kết quả tóm tắt của tất cả các sandbox đã phân tích mẫu
        - Chi tiết hơn get_relationship_id(file_id, relationship='behaviours')
    """
    try:
        file_id = '729f12b7ca02aa43785645aa14c72f414d6336a13d14ed190d634b5724d00a08'
        result = vt.get_behaviour_summary(file_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_get_behaviour_summary.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_behaviours_sandbox():
    """
        - Trả về kết quả phân tích của một sandbox. Tùy sandbox sẽ cho kết quả khác nhau.
        - Cần chỉ định một sandbox, dựa vào sandbox_id. Định dạng: <file-id>_<sandbox-name>
        - Sử dụng get_relationship() hoặc get_relationship_id với relationship='behaviours' để lấy sandbox_id
    """
    try:
        sandbox_id = '729f12b7ca02aa43785645aa14c72f414d6336a13d14ed190d634b5724d00a08_Dr.Web vxCube'
        result = vt.get_behaviours_sandbox(sandbox_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_get_behaviours_sandbox.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_behaviours_sandbox_relationship():
    """
        - https://developers.virustotal.com/v3.0/reference#file-behaviour-summary -> Relationships: file, attack_techniques
    """
    try:
        sandbox_id = '729f12b7ca02aa43785645aa14c72f414d6336a13d14ed190d634b5724d00a08_Dr.Web vxCube'
        relationship = 'attack_techniques'
        result = vt.get_behaviours_sandbox_relationship(sandbox_id, relationship)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_get_behaviours_sandbox_relationship_file.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_behaviours_sandbox_report():
    """
        - Get VT Report dạng HTML theo sandbox_id
        - sandbox_id có được từ method: get_relationship hoặc get_relationship_id với tham số relationship = 'behaviours'
    """
    try:
        # sandbox_id = '729f12b7ca02aa43785645aa14c72f414d6336a13d14ed190d634b5724d00a08_C2AE'
        sandbox_id = '729f12b7ca02aa43785645aa14c72f414d6336a13d14ed190d634b5724d00a08_Dr.Web vxCube'
        # sandbox_id = '729f12b7ca02aa43785645aa14c72f414d6336a13d14ed190d634b5724d00a08_Tencent HABO'
        # sandbox_id = '729f12b7ca02aa43785645aa14c72f414d6336a13d14ed190d634b5724d00a08_VirusTotal Jujubox'
        result = vt.get_behaviours_sandbox_report(sandbox_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            html_report = 'test_get_behaviours_sandbox_report_' + sandbox_id.split('_')[-1].replace(' ', '_') + '.html'
            try:
                with open(os.path.join(TEST_DIR, 'result', html_report), 'wb') as fs:
                    fs.write(result)
            except Exception as err:
                print(err)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_sigma_analyses_id():
    """
        - Lấy kết quả quét bằng sigma của một mẫu
        - Report này đơn giản, ngắn gọn, trả về kèm ID của sigma rules
    """
    try:
        file_id = 'be106bc807b68d8d2bea83f7fbd526675f127b2f234d6c31e2932bb5a5d1aa34'
        relationship = 'rules'
        result = vt.get_sigma_analyses_id(file_id, relationship)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_get_sigma_analyses_id.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_sigma_analyses():
    """
        - Get VT report sau khi phân tích bằng Sigma rules
        - Các sandbox của VT đc cài Sysmon, Sigma rules dựa trên event này để quét.
        - Report này chi tiết hơn 'get_sigma_analyses_id'
    """
    try:
        file_id = 'be106bc807b68d8d2bea83f7fbd526675f127b2f234d6c31e2932bb5a5d1aa34'
        relationship = 'rules'
        result = vt.get_sigma_analyses(file_id, relationship)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_get_sigma_analyses.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_sigma_rule():
    """
        - Lấy thông tin chi tiết về một Sigma rule từ VT
        - Cần phải có rule_id lấy từ: get_sigma_analyses_id
    """
    try:
        rule_id = 'b8f19be4c7bf862dce0d4d1f7885f2207ddf93b3a33d8a6e16f3968c4fbb6491'
        result = vt.get_sigma_rule(rule_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_get_sigma_rule.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_yara_rule():
    """
        - Lấy thông tin chi tiết về một YARA rule từ VT
        - Cần phải có rule_id lấy từ:
    """
    try:
        rule_id = '00060f77d2'
        result = vt.get_yara_rule(rule_id)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_files_test_get_yara_rule_00060f77d2.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')
