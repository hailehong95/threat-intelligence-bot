import errno
import hashlib
import requests

from .vtapibase import VirusTotalAPI
from .vtapierror import VirusTotalAPIError


class VirusTotalAPIEnterprise(VirusTotalAPI):
    """
        Methods:
            get_file_id(): Get SHA256, SHA1 or MD5 file identifier.
            get_download_url(): Get a download URL for a file (special privileges required).
            get_download(): Download a file (special privileges required).
        """

    @staticmethod
    def get_file_id(file_path, hash_alg='sha256'):
        """
        Get SHA256, SHA1 or MD5 file identifier.
        :param file_path: Path to the file to be scanned (str).
        :param hash_alg: Necessary identifier ('sha256', 'sha1' or 'md5'). The default value is 'sha256'.
        :return: The SHA256, SHA1 or MD5 identifier of the file.
        :except: File is not found, do not have access rights to the file, IO error occurs during file operations.
        """
        buffer_size = 65536
        hasher = hashlib.new(hash_alg)
        try:
            with open(file_path, 'rb') as file:
                buffer = file.read(buffer_size)
                while len(buffer) > 0:
                    hasher.update(buffer)
                    buffer = file.read(buffer_size)
        except FileNotFoundError:
            raise VirusTotalAPIError('File not found', errno.ENOENT)
        except PermissionError:
            raise VirusTotalAPIError('Permission error', errno.EPERM)
        except OSError:
            raise VirusTotalAPIError('IO Error', errno.EIO)
        else:
            return hasher.hexdigest()

    @staticmethod
    def save_download_file(bytes_stream, file_path):
        """
        Save bytes stream downloaded to file
        :param bytes_stream: stream bytes, get from 'get_download' method (bytes)
        :param file_path: location to save file (str)
        :return: Number of bytes written
        """
        try:
            with open(file_path, 'wb') as fs:
                fs.write(bytes_stream)
        except OSError:
            raise VirusTotalAPIError('IO Error', errno.EIO)
        else:
            return len(bytes_stream)

    def get_download_url(self, file_id):
        """
        Get a download URL for a file. This function requires special privileges (you need a private key to
            access the VirusTotal API).
        Ref: https://developers.virustotal.com/v3.0/reference#files-download-url
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/files/' + file_id + '/download_url'
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

    def get_download(self, file_id):
        """
        Download a file. This function requires special privileges (you need a private key to access the VirusTotal API).
        Ref: https://developers.virustotal.com/v3.0/reference#files-download
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/files/' + file_id + '/download'
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

    def get_user(self, user_id):
        """
        Retrieve user information
        Ref: https://developers.virustotal.com/v3.0/reference#user
        :param user_id: User ID or API key
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/users/' + user_id
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

    def get_api_usage(self, user_id):
        """
        Retrieve user's API usage
        Ref: https://developers.virustotal.com/v3.0/reference#user-api-usage
        :param user_id: User ID or API key
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/users/' + user_id + '/api_usage'
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

    def get_overall_quotas(self, user_id):
        """
        User's overall quotas.
        Ref: https://developers.virustotal.com/v3.0/reference#get-user-overall-quotas
        :param user_id: User ID or API key
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/users/' + user_id + '/overall_quotas'
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

    def intelligence_file_search(self, query, order='', limit=10, cursor='', descriptors_only=False):
        """
        Search for files. This endpoint is only available for users with special privileges.
        Ref: - https://developers.virustotal.com/v3.0/reference#intelligence-search
             - https://support.virustotal.com/hc/en-us/articles/360001387057-VirusTotal-Intelligence-Introduction
             - https://support.virustotal.com/hc/en-us/articles/360001385897-VT-Intelligence-search-modifiers
        :param query: Search query: Boolean operator: AND, OR, NOT, Grouping parts: ()
        :param order: Sort order
            + file (first_submission_date, last_submission_date (default), positives, times_submitted, size)
            + url: first_submission_date, last_submission_date (default), positives, times_submitted, status
            + domain: creation_date, last_modification_date (default), last_update_date, positives
            + ip: ip, last_modification_date (default), positives
        :param limit: Maximum number of results
        :param cursor: Continuation cursor
        :param descriptors_only: Whether to return full object information or just object descriptors.
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/intelligence/search'
        query_params = {'query': query, 'order': order, 'limit': str(limit), 'cursor': cursor, 'descriptors_only': descriptors_only}
        try:
            response = requests.get(api_url, headers=self.headers, params=query_params, timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def intelligence_zip_files(self, password='infected', hashes=[]):
        """
        Creates a password-protected ZIP file containing files from VirusTotal.
        This endpoint is only available for users with special privileges.
        Ref: - https://developers.virustotal.com/v3.0/reference#intelligence-search-snippets
        :param password: password-protected ZIP file, default is 'infected'
        :param hashes: A list of hashes (SHA-256, SHA-1, or MD5) for the files included in the ZIP
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/intelligence/zip_files'
        data = {"data": {"password": password, "hashes": list(set(hashes))}}
        try:
            response = requests.post(api_url, headers=self.headers, json=data, timeout=self.timeout, proxies=self.proxies)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def intelligence_zip_info(self, zip_id):
        """
        Retrieve information about a ZIP file
        This endpoint is only available for users with special privileges.
        Ref: - https://developers.virustotal.com/v3.0/reference#get-zip-file
        :param zip_id: ZIP file identifier
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/intelligence/zip_files/' + zip_id
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

