import errno
import requests

from .vtapibase import VirusTotalAPI
from .vtapierror import VirusTotalAPIError


class VirusTotalAPIDomains(VirusTotalAPI):
    """
        Methods:
            get_report(): Retrieve information about an Internet domain.
            get_comments(): Retrieve comments for an Internet domain.
            put_comments(): Add a comment to an Internet domain.
            get_relationship(): Retrieve objects related to an Internet domain.
            get_votes(): Retrieve votes for a hostname or domain.
            put_votes(): Add a vote for a hostname or domain.
    """

    def get_report(self, domain):
        """
        Retrieve information about an Internet domain.
        Ref: https://developers.virustotal.com/v3.0/reference#domain-info
        :param domain: Domain name (str).
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors.
        """
        self._last_result = None
        self._last_http_error = None
        api_url = self.base_url + '/domains/' + domain

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

    def get_comments(self, domain, limit=10, cursor='""'):
        """
        Retrieve comments for an Internet domain.
        Ref: https://developers.virustotal.com/v3.0/reference#domains-comments-get
        :param domain: Domain name (str).
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors.
        """
        self._last_result = None
        self._last_http_error = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/domains/' + domain + '/comments'
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

    def put_comments(self, domain, text):
        """
        Add a comment to an Internet domain.
        Ref: https://developers.virustotal.com/v3.0/reference#domains-comments-post
        :param domain: Domain name (str).
        :param text: Text of the comment (str).
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors.
        """
        self._last_http_error = None
        self._last_result = None
        comments = {"data": {'type': 'comment', 'attributes': {'text': text}}}
        api_url = self.base_url + '/domains/' + domain + '/comments'
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

    def get_relationship(self, domain, relationship='resolutions', limit=10, cursor='""'):
        """
        Retrieve related objects to an Internet domain
        Ref:
            - https://developers.virustotal.com/v3.0/reference#domains-relationships
            - https://developers.virustotal.com/v3.0/reference#domains-1 -> Relationships
        :param domain: Domain name (str).
        :param relationship: Relationship name (str). The default value is '/resolutions'.
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/domains/' + domain + '/' + relationship
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

    def get_votes(self, domain, limit=10, cursor='""'):
        """
        Retrieve votes for a hostname or domain.
        Ref: https://developers.virustotal.com/v3.0/reference#domains-votes-get
        :param domain: Domain name (str).
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors.
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/domains/' + domain + '/votes'
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

    def put_votes(self, domain, malicious=False):
        """
        Add a vote for a hostname or domain.
        Ref: https://developers.virustotal.com/v3.0/reference#domain-votes-post
        :param domain: Domain name (str).
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
        api_url = self.base_url + '/domains/' + domain + '/votes'
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
