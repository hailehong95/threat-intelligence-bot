import errno
import hashlib
import requests

from .vtapibase import VirusTotalAPI
from .vtapierror import VirusTotalAPIError


class VirusTotalAPIFiles(VirusTotalAPI):
    """
    Methods:
        get_file_id(): Get SHA256, SHA1 or MD5 file identifier.
        upload(): Upload and analyse a file.
        get_upload_url(): Get a URL for uploading files larger than 32MB.
        get_report(): Retrieve information about a file.
        reanalyse(): Reanalyse a file already in VirusTotal.
        get_comments(): Retrieve comments for a file.
        put_comments(): Add a comment to a file.
        get_votes(): Retrieve votes for a file.
        put_votes(): Add a votes to a file.
        get_relationship(): Retrieve objects related to a file.
        get_behaviours(): Get the PCAP for the sandbox.
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

    def upload(self, file_path):
        """
        Upload and analyse a file.
        Ref: https://developers.virustotal.com/v3.0/reference#files-scan
        :param file_path: Path to the file to be scanned (str).
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors, permission error, IO error
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/files'
        try:
            with open(file_path, 'rb') as file:
                files = {'file': (file_path, file)}
                response = requests.post(api_url, headers=self.headers, files=files, timeout=self.timeout, proxies=self.proxies)
        except FileNotFoundError:
            raise VirusTotalAPIError('File not found', errno.ENOENT)
        except PermissionError:
            raise VirusTotalAPIError('Permission error', errno.EPERM)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        except OSError:
            raise VirusTotalAPIError('IO Error', errno.EIO)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_upload_url(self):
        """
        Get a URL for uploading files larger than 32MB.
        Ref: https://developers.virustotal.com/v3.0/reference#files-upload-url
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/files/upload_url'
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

    def upload_larger_file(self, file_path, upload_url):
        """
        Upload and analyse a file larger than 32MB.
        Ref: https://developers.virustotal.com/v3.0/reference#files-upload-url
        :param file_path: Path to the file (>32MB) to be scanned (str).
        :param upload_url: upload larger file url from get_upload_url() method (str)
        :return: The response from the server as a byte sequence.
        :except: Server connection errors, timeout errors, permission error, IO error
        """
        self._last_http_error = None
        self._last_result = None
        api_url = upload_url
        try:
            with open(file_path, 'rb') as file:
                files = {'file': (file_path, file)}
                response = requests.post(api_url, headers=self.headers, files=files, timeout=self.timeout, proxies=self.proxies)
        except FileNotFoundError:
            raise VirusTotalAPIError('File not found', errno.ENOENT)
        except PermissionError:
            raise VirusTotalAPIError('Permission error', errno.EPERM)
        except requests.exceptions.Timeout:
            raise VirusTotalAPIError('Timeout error', errno.ETIMEDOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalAPIError('Connection error', errno.ECONNABORTED)
        except OSError:
            raise VirusTotalAPIError('IO Error', errno.EIO)
        else:
            self._last_http_error = response.status_code
            self._last_result = response.content
            return response.content

    def get_report(self, file_id):
        """
        Retrieve information about a file.
        Ref: https://developers.virustotal.com/v3.0/reference#file-info
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/files/' + file_id
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

    def analyse(self, file_id):
        """
        Reanalyse a file already in VirusTotal.
        Ref: https://developers.virustotal.com/v3.0/reference#files-analyse
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/files/' + file_id + '/analyse'
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

    def get_comments(self, file_id, limit=10, cursor='""'):
        """
        Retrieve comments for a file.
        Ref: https://developers.virustotal.com/v3.0/reference#files-comments-get
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/files/' + file_id + '/comments'
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

    def put_comments(self, file_id, text):
        """
        Add a comment to a file.
        Ref: https://developers.virustotal.com/v3.0/reference#files-comments-post
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :param text: Text of the comment (str).
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        comments = {"data": {'type': 'comment', 'attributes': {'text': text}}}
        api_url = self.base_url + '/files/' + file_id + '/comments'
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

    def get_votes(self, file_id, limit=10, cursor='""'):
        """
        Retrieve votes for a file.
        Ref: https://developers.virustotal.com/v3.0/reference#files-votes-get
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/files/' + file_id + '/votes'
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

    def put_votes(self, file_id, malicious=False):
        """
        Add a votes to a file.
        Ref: https://developers.virustotal.com/v3.0/reference#files-votes-post
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :param malicious: Determines a malicious (True) or harmless (False) file (bool).
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
        api_url = self.base_url + '/files/' + file_id + '/votes'
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

    def get_relationship(self, file_id, relationship='behaviours', limit=10, cursor=''):
        """
        Retrieve objects related to a file.
        Ref: - https://developers.virustotal.com/v3.0/reference#files-relationships
             - https://developers.virustotal.com/v3.0/reference#files -> Relationships
             - Ex: behaviours, bundled_files, comments, contacted_domains, contacted_ips, contacted_urls, dropped_files
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :param relationship: Relationship name (str). The default value is "/behaviours".
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/files/' + file_id + '/' + relationship
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

    def get_relationship_id(self, file_id, relationship='behaviours', limit=10, cursor=''):
        """
        Retrieve related objects IDs
        Ref: - https://developers.virustotal.com/v3.0/reference#files-relationships-ids
             - https://developers.virustotal.com/v3.0/reference#files -> Relationships
             - Ex: behaviours, bundled_files, comments, contacted_domains, contacted_ips, contacted_urls, dropped_files
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :param relationship: Relationship name (str). The default value is "/behaviours".
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/files/' + file_id + '/relationships/' + relationship
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

    def get_behaviour_summary(self, file_id):
        """
        A summary with behavioural information about the file.
        Ref: https://developers.virustotal.com/v3.0/reference#file-all-behaviours-summary
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/files/' + file_id + '/behaviour_summary'
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

    def get_behaviours_sandbox(self, sandbox_id):
        """
        File behaviour report from a sandbox.
        Ref: https://developers.virustotal.com/v3.0/reference#get-file-behaviour-id
        :param sandbox_id: Identifier obtained using the 'get_relationship' or 'get_relationship_id' method with the
            value of the 'relationship' argument equal to 'behaviours' (str).
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/file_behaviours/' + sandbox_id
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

    def get_behaviours_sandbox_relationship(self, sandbox_id, relationship='file'):
        """
        Retrieve objects related to a file behaviour
        Ref: - https://developers.virustotal.com/v3.0/reference#file_behaviourssandbox_idrelationship
             - https://developers.virustotal.com/v3.0/reference#file-behaviour-summary -> Relationships: file, attack_techniques
             - Ex: behaviours, bundled_files, comments, contacted_domains, contacted_ips, contacted_urls, dropped_files
        :param sandbox_id: Identifier obtained using the 'get_relationship' method with the value of the 'relationship'
            argument equal to 'behaviours' (str).
        :param relationship: Relationship name (str). The default value is "/pcap".
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/file_behaviours/' + sandbox_id + '/' + relationship
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

    def get_behaviours_sandbox_report(self, sandbox_id):
        """
        HTML sandbox report
        Ref: https://developers.virustotal.com/v3.0/reference#get-file-behaviour-html
        :param sandbox_id: Identifier obtained using the 'get_relationship' or 'get_relationship_id' method with the
            value of the 'relationship' argument equal to 'behaviours' (str).
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/file_behaviours/' + sandbox_id + '/html'
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

    def get_sigma_analyses_id(self, file_id, relationship='rules', limit=10, cursor=''):
        """
        Retrieve object descriptors related to a Sigma analysis
        Ref: - https://developers.virustotal.com/v3.0/reference#get-sigma-relationships-ids
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :param relationship: Relationship name (str). The default value is "rules".
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/sigma_analyses/' + file_id + '/relationships/' + relationship
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

    def get_sigma_analyses(self, file_id, relationship='rules', limit=10, cursor=''):
        """
        Retrieve objects related to a Sigma analysis
        Ref: - https://developers.virustotal.com/v3.0/reference#get-sigma-relationships
        :param file_id: SHA-256, SHA-1 or MD5 identifying the file (str).
        :param relationship: Relationship name (str). The default value is "rules".
        :param limit: Maximum number of comments to retrieve (int). The default value is 10.
        :param cursor: Continuation cursor (str). The default value is ''.
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        query_string = {'limit': str(limit), 'cursor': cursor}
        api_url = self.base_url + '/sigma_analyses/' + file_id + '/' + relationship
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

    def get_sigma_rule(self, rule_id):
        """
        Retrive a Sigma rule by ID
        Ref: https://developers.virustotal.com/v3.0/reference#get-sigma-rules
        :param rule_id: Identifier Sigma rule. Value of the 'get_sigma_analyses_id'
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/sigma_rules/' + rule_id
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

    def get_yara_rule(self, rule_id):
        """
        Fetch a YARA ruleset by ID.
        Ref: https://developers.virustotal.com/v3.0/reference#get-yara-rulesets
        :param rule_id: Identifier YARA rule. Value of the ''
        :return: The response from the server as a byte sequence.
        :except: Connection errors, timeout errors
        """
        self._last_http_error = None
        self._last_result = None
        api_url = self.base_url + '/yara_rulesets/' + rule_id
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

