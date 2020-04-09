from .format_base import FormatBase

class NoneType(FormatBase):
    def __init__(self, attestation_object, authenticator_data):
        super().__init__(attestation_object, authenticator_data)
    

    '''
     * returns the key certificate in PEM format
     * @return string
     '''
    def getCertificatePem(self):
        return None

    '''
     * @param string clientDataHash
     '''
    def validateAttestation(self, clientDataHash):
        return True

    '''
     * validates the certificate against root certificates
     * @param array $rootCas
     * @return boolean
     * @throws WebAuthnException
     '''
    def validateRootCertificate(self, rootCas):
        return True
