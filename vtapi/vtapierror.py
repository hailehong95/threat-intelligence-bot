
class VirusTotalAPIError(Exception):

    def __init__(self, message, err_code):
        super().__init__(message)
        self.err_code = err_code
