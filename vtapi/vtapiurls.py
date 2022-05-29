import errno
import base64
import hashlib
import requests

from .vtapibase import VirusTotalAPI
from .vtapierror import VirusTotalAPIError


class VirusTotalAPIUrls(VirusTotalAPI):
    """
    Methods:
        get_url_id_base64(): Get base64 encoded URL identifier.
        get_url_id_sha256(): Get the URL identifier as a SHA256 hash.
        upload(): Upload URL for analysis.
        get_report(): Retrieve information about an URL.
        analyse(): Analyse an URL.
        get_comments(): Retrieve comments for an URL.
        put_comments(): Add a comment to a URL.
        get_votes(): Retrieve votes for an URL.
        put_votes(): Add a votes to a URL.
        get_relationship(): Retrieve objects related to an URL
    """

    @staticmethod
    def get_url_id_base64(url):
        """
        Get base64 encoded URL identifier.
        :param url: The URL for which you want to get the identifier (str).
        :return: The identifier of the url, base64 encoded (str).
        """
        return base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8').rstrip('=')

    @staticmethod
    def get_url_id_sha256(url):
        """
        Get the URL identifier as a SHA256 hash.
        :param url: The URL for which you want to get the identifier (str).
        :return: The identifier of the url, SHA256 encoded (str).
        """
        return hashlib.sha256(url.encode()).hexdigest()

    def upload(self, url):
        """
        Upload URL for analysis.
        Ref: https://developers.virustotal.com/v3.0/reference#urls
        :param url: URL to be analyzed (str).
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        data = {'url': url}
        api_url = self.base_url + '/urls'
        try:
            response = requests.post(api_url, headers=self.headers, data=data, timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_report(self, url_id):
        """
        Retrieve information about an URL.
        Ref: https://developers.virustotal.com/v3.0/reference#url-info
        :param url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL
            (method 'get_url_id_sha256()'), the string resulting from encoding the URL in base64 without the "=" padding
            (method 'get_url_id_base64()').
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/urls/' + url_id
        try:
            response = requests.get(api_url, headers=self.headers, timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def analyse(self, url_id):
        """
        Reanalyse a URL.
        Ref: https://developers.virustotal.com/v3.0/reference#urls-analyse
        :param url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL
            (method 'get_url_id_sha256()'), the string resulting from encoding the URL in base64 without the "=" padding
            (method 'get_url_id_base64()').
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/urls/' + url_id + '/analyse'
        try:
            response = requests.post(api_url, headers=self.headers, timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_comments(self, url_id, limit=10, cursor='""'):
        """
        Retrieve comments for an URL.
        Ref: https://developers.virustotal.com/v3.0/reference#urls-comments-get
        :param url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL
            (method 'get_url_id_sha256()'), the string resulting from encoding the URL in base64 without the "=" padding
            (method 'get_url_id_base64()').
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/urls/' + url_id + '/comments'
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string, timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def put_comments(self, url_id, text):
        """
        Add a comment to a URL.
        Ref: https://developers.virustotal.com/v3.0/reference#urls-comments-post
        :param url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL
            (method 'get_url_id_sha256()'), the string resulting from encoding the URL in base64 without the "=" padding
            (method 'get_url_id_base64()').
        :param text: Text of the comment (str).
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        comments = {"data": {'type': 'comment', 'attributes': {'text': text}}}
        api_url = self.base_url + '/urls/' + url_id + '/comments'
        try:
            response = requests.post(api_url, headers=self.headers, json=comments, timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_votes(self, url_id, limit=10, cursor='""'):
        """
        Retrieve votes for a URL.
        Ref: https://developers.virustotal.com/v3.0/reference#urls-votes-get
        :param url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL
            (method 'get_url_id_sha256()'), the string resulting from encoding the URL in base64 without the "=" padding
            (method 'get_url_id_base64()').
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/urls/' + url_id + '/votes'
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string, timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def put_votes(self, url_id, malicious=False):
        """
        Add a vote for a URL.
        Ref: https://developers.virustotal.com/v3.0/reference#urls-votes-post
        :param url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL
            (method 'get_url_id_sha256()'), the string resulting from encoding the URL in base64 without the "=" padding
            (method 'get_url_id_base64()').
        :param malicious: Determines a malicious (True) or harmless (False) URL (bool).
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        if malicious:
            verdict = 'malicious'
        else:
            verdict = 'harmless'
        votes = {'data': {'type': 'vote', 'attributes': {'verdict': verdict}}}
        api_url = self.base_url + '/urls/' + url_id + '/votes'
        try:
            response = requests.post(api_url, headers=self.headers, json=votes, timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_relationship(self, url_id, relationship='network_location', limit=10, cursor='""'):
        """
        Retrieve objects related to an URL
        Ref:
            - https://developers.virustotal.com/v3.0/reference#urls-relationships
            - https://developers.virustotal.com/v3.0/reference#url-object -> Relationships (table)
        :param url_id: URL identifier (str). This identifier can adopt two forms: the SHA-256 of the canonized URL
            (method 'get_url_id_sha256()'), the string resulting from encoding the URL in base64 without the "=" padding
            (method 'get_url_id_base64()').
        :param relationship: Relationship name (str). The default value is '/last_serving_ip_address'.
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/urls/' + url_id + '/' + relationship
        try:
            response = requests.get(api_url, headers=self.headers, params=query_string, timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_analyse_object_report(self, object_id):
        """
        Retrieve information about a file or URL analysis
        Ref: https://developers.virustotal.com/v3.0/reference#analysis
        :param object_id: URL identifier (str). This identifier. Result of: upload(url), analyse(url_id)
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/analyses/' + object_id
        try:
            response = requests.get(api_url, headers=self.headers, timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content
