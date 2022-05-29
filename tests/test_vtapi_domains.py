#!/usr/bin/env python

import os
import json
import vtapi

from tests.test_vtapi_config import read_config, JSON_FILE
from tests.test_vtapi_config import write_config as write_report

TEST_DIR = os.path.dirname(os.path.realpath(__file__))

api_key = read_config(JSON_FILE)[1]['api_key']
vt = vtapi.VirusTotalAPIDomains(api_key)


def test_get_report():
    try:
        domain = 'fril.zarykon.com'
        result = vt.get_report(domain)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_domains_test_get_report.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_comments():
    try:
        domain = 'fril.zarykon.com'
        result = vt.get_comments(domain, 5)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_domains_test_get_comments.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_put_comments():
    try:
        domain = 'fril.zarykon.com'
        text = 'Malware C2'
        result = vt.put_comments(domain, text)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_domains_test_put_comments.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_relationship():
    """
        - Relationships: communicating_files, comments, resolutions,.v.v..
        - Ref: https://developers.virustotal.com/v3.0/reference#domains-1 -> Relationships
    """
    try:
        domain = 'fril.zarykon.com'
        relationship = 'comments'
        result = vt.get_relationship(domain, relationship)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_domains_test_get_relationship_comments.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_get_votes():
    try:
        domain = 'google.com'
        result = vt.get_votes(domain)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_domains_test_get_votes.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')


def test_put_votes():
    try:
        domain = 'google.com'
        result = vt.put_votes(domain, False)
    except vtapi.VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt.get_last_http_error() == vt.HTTP_OK:
            result = json.loads(result)
            write_report(os.path.join(TEST_DIR, 'result', 'vtapi_domains_test_put_votes.json'), result)
            # result = json.dumps(result, sort_keys=False, indent=4)
            # print(result)
        else:
            print('HTTP Error [' + str(vt.get_last_http_error()) + ']')
