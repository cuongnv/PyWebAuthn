from .format_base import FormatBase
from fido2.errors.errors import ErrCodes, WebAuthnException
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends.openssl.hashes import hashes
from cryptography.exceptions import InvalidSignature

#ref https://medium.com/@herrjemand/verifying-fido-u2f-attestations-in-fido2-f83fab80c355
class U2F(FormatBase):
    _SHA256_cose_identifier = -7
    
    def __init__(self, attestation_object, authenticator_data):
        super().__init__(attestation_object, authenticator_data)
        att_stmt = self._attestation_object['attStmt']

        if 'alg' in att_stmt and att_stmt['alg'] != self._SHA256_cose_identifier: # SHA256
            raise WebAuthnException('only SHA256 acceptable but got: ' + att_stmt['alg'], ErrCodes.INVALID_DATA)

        if 'sig' not in att_stmt:
            raise WebAuthnException('No signature found', ErrCodes.INVALID_DATA)

        if 'x5c' not in att_stmt or len(att_stmt['x5c']) < 1:
            raise WebAuthnException('invalid x5c certificate', ErrCodes.INVALID_DATA)

        self._signature = att_stmt['sig']
        self._x5c = att_stmt['x5c'][0]

    '''
     * returns the key certificate in PEM format
     * @return string
     '''
    def getCertificatePem(self):
        cert = self._createCertificatePem(self._x5c)
        return cert

    '''
     * @param string $clientDataHash
    '''
    def validateAttestation(self, clientDataHash):
        cert = x509.load_pem_x509_certificate(self.getCertificatePem(), default_backend())
        public_key = cert.public_key()
        if not public_key:
            raise WebAuthnException('invalid public key: ', ErrCodes.INVALID_PUBLIC_KEY)

        verify_data = b"\x00" + self._authenticator_data.getRpIdHash() + clientDataHash \
            + self._authenticator_data.getCredentialId() + self._authenticator_data.getPublicKeyU2F()
        try:
            public_key.verify(self._signature, verify_data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            raise e