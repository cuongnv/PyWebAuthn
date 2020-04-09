class ErrCodes:
    UNKNOWN_ERROR = 0
    INVALID_DATA = 1
    CREDENTIAL_NOT_INCLUDE=2
    MISSING_ATTESTED_DATA=3
    INVALID_PUBLIC_KEY=4
    INVALID_CERTIFICATE_CHAIN=5
class WebAuthnException(RuntimeError):
    
    def __init__(self, msg, code = ErrCodes.UNKNOWN_ERROR):
        """Constructs a WebAuthnException

        Args:
            msg (str): The human-readable error message
        """
        super(WebAuthnException, self).__init__("%d: %s" % (code, msg))
        self.code = code
        self.msg = msg
    
