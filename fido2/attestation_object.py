'''
 * @author cuongnv
 * @license https://github.com/cuongnv/PyWebAuthn/blob/master/LICENSE MIT
 '''
import fido2.cbor.cbor as cbor
from fido2.errors.errors import ErrCodes, WebAuthnException
from .authenticator_data import AuthenticatorData
from .formats.nonetype import NoneType 
from .formats.u2f import U2F
from .formats.android_key import AndroidKey
from .formats.packed import Packed
from .formats.android_safety_net import AndroidSafetyNet
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class AttestationObject(object):
    def __init__(self, binary, allowFormat = ['none', 'android-key', 'packed', 'fido-u2f', 'android-safetynet']):
        self.allowedFormats = allowFormat
        self.authenticatorData = {}
        self.attestationFormat = {}
        enc = cbor.loads(binary)
        #validation
        if not isinstance(enc, dict) or 'fmt' not in enc:
            raise WebAuthnException('invalid attestation format', ErrCodes.INVALID_DATA)
        
        if 'attStmt' not in enc:
            raise WebAuthnException('invalid attestation format (attStmt not available)', ErrCodes.INVALID_DATA)

        if 'authData' not in enc:
            raise WebAuthnException('invalid attestation format (authData not available)', ErrCodes.INVALID_DATA)

        self._authenticatorData = AuthenticatorData(enc['authData'])

        if enc['fmt'] not in self.allowedFormats:
            raise WebAuthnException('invalid atttestation format: ' + enc['fmt'], ErrCodes.INVALID_DATA)

        if enc['fmt'] == 'none':
            self._attestationFormat = NoneType(enc, self._authenticatorData)
        elif enc['fmt'] == 'fido-u2f':
            self._attestationFormat = U2F(enc, self._authenticatorData)
        elif enc['fmt'] == 'packed':
            self._attestationFormat = Packed(enc, self._authenticatorData)
        elif enc['fmt'] == 'android-key':
            self._attestationFormat = AndroidKey(enc, self._authenticatorData)
        elif enc['fmt'] == 'android-safetynet':
            self._attestationFormat = AndroidSafetyNet(enc, self._authenticatorData)
        else:
            raise WebAuthnException('atttestation format: ' + enc['fmt'] + ' not supported', ErrCodes.INVALID_DATA)


    '''
     * returns the attestation public key in PEM format
     * @return AuthenticatorData
     '''
    def getAuthenticatorData(self):
        return self._authenticatorData

    '''
     * returns the certificate chain as PEM
     * @return string|null
     '''
    def getCertificateChain(self):
        return self._attestationFormat.getCertificateChain()

    '''
     * return the certificate issuer as string
     * @return string
     '''
    def getCertificateIssuer(self):
        pem = self.getCertificatePem()
        issuer = ''
        if pem:
            cert = x509.load_pem_x509_certificate(pem, default_backend())
            issuer = cert.issuer.rfc4514_string()
        return issuer
    

    '''
     * return the certificate subject as string
     * @return string
     '''
    def getCertificateSubject(self):
        pem = self.getCertificatePem()
        subject = ''
        if pem:
            cert = x509.load_pem_x509_certificate(pem, default_backend())
            subject = cert.subject.rfc4514_string()
        return subject
    

    '''
     * returns the key certificate in PEM format
     * @return string
     '''
    def getCertificatePem(self):
        return self._attestationFormat.getCertificatePem()

    '''
     * checks validity of the signature
     * @param string clientDataHash
     * @return bool
     * @throws WebAuthnException
     '''
    def validateAttestation(self, clientDataHash):
        return self._attestationFormat.validateAttestation(clientDataHash)
    

    '''
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws WebAuthnException
     '''
    def validateRootCertificate(self, rootCas):
        return self._attestationFormat.validateRootCertificate(rootCas)
    

    '''
     * checks if the RpId-Hash is valid
     * @param string$rpIdHash
     * @return bool
     '''
    def validateRpIdHash(self, rpIdHash):
        return rpIdHash == self._authenticatorData.getRpIdHash()
    
