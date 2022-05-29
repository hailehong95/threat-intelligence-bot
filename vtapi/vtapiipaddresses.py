import errno
import requests

from .vtapibase import VirusTotalAPI
from .vtapierror import VirusTotalAPIError


class VirusTotalAPIIPAddresses(VirusTotalAPI):
    """
    The retrieving information about any IP addresses from the VirusTotal database methods are defined in the class.
       Methods:
           get_report(): Retrieve information about an IP address.
           get_comments(): Retrieve comments for an IP address.
           put_comments(): Add a comment to an IP address.
           get_relationship(): Retrieve objects related to an IP address.
           get_votes(): Retrieve votes for an IP address.
           put_votes(): Add a vote for an IP address.
    """

    def get_report(self, ip_address):
        """
        Retrieve information about an IP address.
        Ref: https://developers.virustotal.com/v3.0/reference#ip-info
        :param ip_address: IP address (str).
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors.
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/ip_addresses/' + ip_address
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

    def get_comments(self, ip_address, limit=10, cursor='""'):
        """
        Retrieve comments for an IP address.
        Ref: https://developers.virustotal.com/v3.0/reference#ip-comments-get
        :param ip_address: IP address (str).
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/ip_addresses/' + ip_address + '/comments'
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

    def put_comments(self, ip_address, text):
        """
        Add a comment to an IP address.
        Ref: https://developers.virustotal.com/v3.0/reference#ip-comments-post
        :param ip_address: IP address (str).
        :param text: Text of the comment (str).
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors.
        """
        self._last_http_error = None
        self._last_result = None
        comments = {"data": {'type': 'comment', 'attributes': {'text': text}}}
        api_url = self.base_url + '/ip_addresses/' + ip_address + '/comments'
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

    def get_relationship(self, ip_address, relationship='resolutions', limit=10, cursor='""'):
        """
        Retrieve objects related to an IP address.
        Ref:
            - https://developers.virustotal.com/v3.0/reference#ip-relationships
            - https://developers.virustotal.com/v3.0/reference#ip-object -> Relationships
        :param ip_address: IP address (str).
        :param relationship: Relationship name (str). The default value is '/resolutions'.
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/ip_addresses/' + ip_address + '/' + relationship
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

    def get_votes(self, ip_address, limit=10, cursor='""'):
        """
        Retrieve votes for an IP address.
        Ref: https://developers.virustotal.com/v3.0/reference#ip-votes
        :param ip_address: IP address (str).
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/ip_addresses/' + ip_address + '/votes'
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

    def put_votes(self, ip_address, malicious=False):
        """
        Add a vote for an IP address.
        Ref: https://developers.virustotal.com/v3.0/reference#ip-votes-post
        :param ip_address: IP address (str).
        :param malicious: Determines a malicious (True) or harmless (False) domain (bool).
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors.
        """
        self._last_http_error = None
        self._last_result = None
        if malicious:
            verdict = 'malicious'
        else:
            verdict = 'harmless'
        votes = {'data': {'type': 'vote', 'attributes': {'verdict': verdict}}}
        api_url = self.base_url + '/ip_addresses/' + ip_address + '/votes'
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
