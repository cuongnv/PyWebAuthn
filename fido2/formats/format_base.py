import os
from abc import ABC, abstractclassmethod, abstractmethod
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import tempfile

class FormatBase(ABC):
    def __init__(self, attestation_object, authenticator_data):
        self._attestation_object = attestation_object
        self._authenticator_data = authenticator_data
        self._x5c_chain = []
        self._x5c_tempFile = None

    def getCertificateChain(self):
        if os.path.exists(self._x5c_tempFile):
            content = ""
            with open(self._x5c_tempFile, 'rb') as f:
                content = f.read()
            return content
        return None

    '''
     returns the key X.509 certificate in PEM format
     @return string
    '''
    @abstractmethod
    def getCertificatePem(self):
        #need to be overwritten
        return None

    '''
     * checks validity of the signature
     * @param string $clientDataHash
     * @return bool
     * @throws WebAuthnException
    '''
    @abstractmethod
    def validateAttestation(self, clientDataHash):
        #need to be overwritten
        return False

    '''
     * create a PEM encoded certificate with X.509 binary data
     * @param string x5c
     * @return bytes string
     '''
    def _createCertificatePem(self, x5c):
        pem = b'-----BEGIN CERTIFICATE-----\n'
        idx = 0
        tmp_x5c = base64.b64encode(x5c)
        length = len(tmp_x5c)
        while((idx+64) <= length):
            pem +=  tmp_x5c[idx:idx+64] + b"\n"
            idx = idx+64
        if tmp_x5c[idx:]:
            if(tmp_x5c[-1:]) == b'\n':
                pem +=  tmp_x5c[idx:]
            else:
                pem +=  tmp_x5c[idx:] + b"\n"
        pem += b'-----END CERTIFICATE-----\n'
        return pem

    '''
     * creates a PEM encoded chain file
     * @return type
    '''
    #TODO need to double check implement is ok or not
    def _createX5cChainFile(self):
        content = b''
        if isinstance(self._x5c_chain, list) and len(self._x5c_chain) > 0:
            for x5c in self._x5c_chain:
                cert = x509.load_pem_x509_certificate(self._createCertificatePem(x5c), default_backend())
                # check if issuer = subject (self signed)
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                selfSigned = True
                if issuer != subject:
                    selfSigned = False
                    
                # if not selfSigned:
                content = content + b"\n" + self._createCertificatePem(x5c) + b"\n"

        if content != b'':
            self._x5c_tempFile = "temp_file"
            tempFile = open(self._x5c_tempFile, "wb")
            tempFile.write(content)
            tempFile.close()
            return self._x5c_tempFile

        return None