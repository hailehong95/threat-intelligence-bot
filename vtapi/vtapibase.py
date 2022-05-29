import requests


class VirusTotalAPI:
    """
        For more about HTTP statuses: https://github.com/psf/requests/blob/master/requests/status_codes.py
    """
    HTTP_OK = requests.codes['ok']
    HTTP_BAD_REQUEST_ERROR = requests.codes['bad_request']
    HTTP_AUTHENTICATION_REQUIRED_ERROR = requests.codes['unauthorized']
    HTTP_FORBIDDEN_ERROR = requests.codes['forbidden']
    HTTP_NOT_FOUND_ERROR = requests.codes['not_found']
    HTTP_ALREADY_EXISTS_ERROR = requests.codes['conflict']
    HTTP_QUOTA_EXCEEDED_ERROR = requests.codes['too_many_requests']
    HTTP_TRANSIENT_ERROR = requests.codes['service_unavailable']

    def __init__(self, api_key=None, timeout=None, proxies=None):
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.headers = {'x-apikey': api_key}
        self.timeout = timeout
        self.proxies = proxies
        self._version_api = '3.0'
        self._last_http_error = None
        self._last_result = None

    def get_version_api(self):
        return self._version_api

    def get_last_http_error(self):
        return self._last_http_error

    def get_last_result(self):
        return self._last_result
