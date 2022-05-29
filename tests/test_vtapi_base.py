#!/usr/bin/env python

from vtapi import __author__, __version__, __title__

import vtapi


def test_base_att():
    print(__title__)
    print(__version__)
    print(__author__)


def test_base_method():
    vt = vtapi.VirusTotalAPI('api-key')
    version = vt.get_version_api()
    last_res = vt.get_last_result()
    last_err = vt.get_last_http_error()
    print(version, last_res, last_err)
