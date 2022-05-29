import errno
import requests

from .vtapibase import VirusTotalAPI
from .vtapierror import VirusTotalAPIError


class VirusTotalAPIComments(VirusTotalAPI):
    """
    Methods:

    """
    def get_comments(self, limit=10, filter='""', cursor='""'):
        """
        Retrieves information about the latest comments.
        Ref: https://developers.virustotal.com/v3.0/reference#get-comments
        :param limit: Number of items to retrieve
        :param filter: Filter returned elements
        :param cursor: Continuation cursor
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/comments'
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

    def delete_comments(self, comment_id):
        """
        Delete a comment.
        Ref: https://developers.virustotal.com/v3.0/reference#comment-id-delete
        :param comment_id: Comment ID (str).
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors.
        """
        self._last_result = None
        self._last_http_error = None
        api_url = self.base_url + '/comments/' + comment_id

        try:
            response = requests.delete(api_url, headers=self.headers, timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content
