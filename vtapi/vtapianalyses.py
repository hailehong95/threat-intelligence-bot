import errno
import requests

from .vtapibase import VirusTotalAPI
from .vtapierror import VirusTotalAPIError


class VirusTotalAPIAnalyses(VirusTotalAPI):
    """
        Methods:
            get_report(): Retrieve information about a file or URL analysis.
    """

    def get_report(self, object_id):
        """
        Retrieve information about a file or URL analysis.
        Ref: https://developers.virustotal.com/v3.0/reference#analysis
        :param object_id: Analysis identifier (str).
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, Timeout errors.
        """
        self._last_result = None
        self._last_http_error = None
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
