from .format_base import FormatBase
from fido2.errors.errors import ErrCodes, WebAuthnException
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends.openssl.hashes import hashes
from cryptography.exceptions import InvalidSignature

class Packed(FormatBase):
    _SHA256_cose_identifier = -7

    def __init__(self, attestation_object, authenticator_data):
        super().__init__(attestation_object, authenticator_data)
        # check u2f data
        att_stmt = self._attestation_object['attStmt']

        if 'alg' in att_stmt and att_stmt['alg'] != self._SHA256_cose_identifier: # SHA256
            raise WebAuthnException('only SHA256 acceptable but got: ' + att_stmt['alg'], ErrCodes.INVALID_DATA)

        if 'sig' not in att_stmt:
            raise WebAuthnException('No signature found', ErrCodes.INVALID_DATA)

        if 'x5c' not in att_stmt or len(att_stmt['x5c']) < 1:
            raise WebAuthnException('invalid x5c certificate', ErrCodes.INVALID_DATA)

        self._signature = att_stmt['sig']
        self._x5c = att_stmt['x5c'][0]

        if len(att_stmt['x5c']) > 1:
            for x5c in att_stmt['x5c']:
                self._x5c_chain.append(x5c)

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

        verify_data = self._authenticator_data.getBinary() + clientDataHash
        try:
            public_key.verify(self._signature, verify_data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            raise e
