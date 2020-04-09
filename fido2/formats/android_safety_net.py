from .format_base import FormatBase
from fido2.errors.errors import ErrCodes, WebAuthnException
import base64, json, hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends.openssl.hashes import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class AndroidSafetyNet(FormatBase):
    def __init__(self, attestation_object, authenticator_data):
        super().__init__(attestation_object, authenticator_data)
        att_stmt = self._attestation_object['attStmt']

        if 'ver' not in att_stmt:
            raise WebAuthnException('invalid Android Safety Net Format ', ErrCodes.INVALID_DATA)
        
        if 'response' not in att_stmt:
            raise WebAuthnException('invalid Android Safety Net Format ', ErrCodes.INVALID_DATA)

        response = att_stmt['response']
        # Response is a JWS [RFC7515] object in Compact Serialization.
        # JWSs have three segments separated by two period ('.') characters
        
        parts = response.decode('ascii').split('.')
        if len(parts) != 3:
            raise WebAuthnException('invalid JWS data', ErrCodes.INVALID_DATA)

        header = base64.b64decode(parts[0] + '===',altchars="-_").decode('ascii')
        payload = base64.b64decode(parts[1] + '===',altchars="-_").decode('ascii')
        self._signature = base64.b64decode(parts[2] + '===', altchars="-_")
        self._signedValue = bytes(parts[0] + '.' + parts[1], 'ascii')

        header = json.loads(header)
        payload = json.loads(payload)
        if 'x5c' not in header:
            raise WebAuthnException('No X.509 signature in JWS Header', ErrCodes.INVALID_DATA)

        if 'alg' not in header or header['alg'] not in ['RS256', 'ES256']:
            raise WebAuthnException('invalid JWS algorithm ' . header['alg'], ErrCodes.INVALID_DATA)

        self._x5c = base64.b64decode(header['x5c'][0])
        self._payload = payload

        if len(header['x5c']) > 1:
            for x5c in header['x5c']:
                self._x5c_chain.append(base64.b64decode(x5c))

    '''
     * returns the key certificate in PEM format
     * @return string
     '''
    def getCertificatePem(self):
        cert = self._createCertificatePem(self._x5c)
        return cert

    '''
     * @param string $clientDataHash
     * ref: https://medium.com/@herrjemand/verifying-fido2-safetynet-attestation-bd261ce1978d
    '''
    def validateAttestation(self, clientDataHash):
        cert = x509.load_pem_x509_certificate(self.getCertificatePem(), default_backend())
        public_key = cert.public_key()
        if not public_key:
            raise WebAuthnException('invalid public key: ', ErrCodes.INVALID_PUBLIC_KEY)

        
        # Verify that the nonce in the response is identical to the Base64 encoding
        # of the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
        
        m = hashlib.sha256()
        m.update(self._authenticator_data.getBinary() + clientDataHash)
        hash_data = m.digest()
        if 'nonce' not in self._payload or bytes(self._payload['nonce'], 'ascii') != base64.b64encode(hash_data):
            raise WebAuthnException('invalid nonce in JWS payload', ErrCodes.INVALID_DATA)

        if 'ctsProfileMatch' not in self._payload or not self._payload['ctsProfileMatch']:
            raise WebAuthnException('invalid ctsProfileMatch in payload', ErrCodes.INVALID_DATA)

        CN = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(CN) == 0 or CN[0].value != 'attest.android.com':
            raise WebAuthnException('The common name is not set to "attest.android.com"!', ErrCodes.INVALID_DATA)

        try:
            public_key.verify(self._signature, self._signedValue, 
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            raise e