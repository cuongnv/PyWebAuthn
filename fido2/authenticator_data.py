'''
 * @author cuongnv
 * @license https://github.com/cuongnv/PyWebAuthn/blob/master/LICENSE MIT
 '''
import base64
import struct
import fido2.cbor.cbor as cbor
from fido2.errors.errors import ErrCodes, WebAuthnException

class AuthenticatorData(object):
    COSE_KTY = 1
    COSE_ALG = 3
    COSE_CRV = -1
    COSE_X = -2
    COSE_Y = -3
    EC2_TYPE = 2
    EC2_ES256 = -7
    EC2_P256 = 1

    def __init__(self, binary):
        super().__init__()
        if not isinstance(binary, bytes) or len(binary) < 37:
            raise WebAuthnException("Invalid authenticatorData input", ErrCodes.INVALID_DATA)

        self._binary = binary
        # Read infos from binary
        # https://www.w3.org/TR/webauthn/#sec-authenticator-data
        # https://medium.com/@herrjemand/verifying-fido2-responses-4691288c8770
        #RP ID
        self._rpIdHash = binary[0:32]
        #flags (1 byte)
        flags = struct.unpack(">B", binary[32:33])[0]
        self._flags = self._readFlags(flags)
        # signature counter: 4 bytes unsigned big-endian integer.
        self._signCount = struct.unpack(">I", binary[33:37])[0]
        offset = 37
        # https://www.w3.org/TR/webauthn/#sec-attested-credential-data
        self._attestedCredentialData = None
        if self._flags['attestedDataIncluded']:
            self._attestedCredentialData, offset = self._readAttestData(binary, offset)
        
        self._extensionData = None
        if self._flags['extensionDataIncluded']:
            self._extensionData = self._readExtensionData(binary[offset:])

    '''
     * Authenticator Attestation Globally Unique Identifier, a unique number
     * that identifies the model of the authenticator (not the specific instance
     * of the authenticator)
     * The aaguid may be 0 if the user is using a old u2f device and/or if
     * the browser is using the fido-u2f format.
     * @return string
     * @throws WebAuthnException
    '''
    def getAAGUID(self):
        if self._attestedCredentialData == None:
            raise WebAuthnException("credential id not included in authenticator data", ErrCodes.CREDENTIAL_NOT_INCLUDE)
        return self._attestedCredentialData["aaguid"]
    

    '''
     * returns the authenticatorData as binary
     * @return string
    '''
    def getBinary(self):
        return self._binary

    '''
     * returns the credentialId
     * @return string
     * @throws WebAuthnException
    '''
    def getCredentialId(self):
        if self._attestedCredentialData == None:
            raise WebAuthnException("credential id not included in authenticator data", ErrCodes.CREDENTIAL_NOT_INCLUDE)
        return self._attestedCredentialData["credentialId"]
    

    '''
     * returns the public key in PEM format
     * @return string
     '''
    def getPublicKeyPem(self):
        der = self._der_sequence(
                self._der_sequence(
                    self._der_oid(b"\x2A\x86\x48\xCE\x3D\x02\x01") + # OID 1.2.840.10045.2.1 ecPublicKey
                    self._der_oid(b"\x2A\x86\x48\xCE\x3D\x03\x01\x07")  # 1.2.840.10045.3.1.7 prime256v1
                ) +
                self._der_bitString(self.getPublicKeyU2F())
            )

        pem = '-----BEGIN PUBLIC KEY-----' + "\n";
        tmp = base64.b64encode(der).decode("ascii")
        length = len(tmp)
        idx = 0
        while((idx+64) <= length):
            pem +=  tmp[idx:idx+64] + "\n"
            idx = idx+64
        pem +=  tmp[idx:] + "\n"
        pem += '-----END PUBLIC KEY-----' + "\n";
        return pem
    

    '''
     * returns the public key in U2F format
     * @return string
     * @throws WebAuthnException
     '''
    def getPublicKeyU2F(self):
        if self._attestedCredentialData == None:
            raise WebAuthnException("credential id not included in authenticator data", ErrCodes.CREDENTIAL_NOT_INCLUDE)
        # ECC uncompressed
        return b"\x04" + self._attestedCredentialData['credentialPublicKey']['x'] + self._attestedCredentialData['credentialPublicKey']['y']
    
    '''
     * returns the SHA256 hash of the relying party id (=hostname)
     * @return string
    '''
    def getRpIdHash(self):
        return self._rpIdHash

    '''
     * returns the sign counter
     * @return int
     '''
    def getSignCount(self):
        return self._signCount

    '''
     * returns true if the user is present
     * @return boolean
     '''
    def getUserPresent(self):
        return self._flags['userPresent']
    

    '''
     * returns true if the user is verified
     * @return boolean
    '''
    def getUserVerified(self):
        return self._flags['userVerified']

    # -----------------------------------------------
    # PRIVATE
    # -----------------------------------------------

    '''
     * reads the flags from flag byte
     * @param string $binFlag
     * @return \stdClass
     '''
    def _readFlags(self, binFlag):
        flags = {
            'bit_0':0,
            'bit_1':0,
            'bit_2':0,
            'bit_3':0,
            'bit_4':0,
            'bit_5':0,
            'bit_6':0,
            'bit_7':0,
            'userPresent':0,
            'userVerified':0,
            'attestedDataIncluded':0,
            'extensionDataIncluded':0
        }

        flags['bit_0'] = (binFlag & 1 << 0) != 0
        flags['bit_1'] = (binFlag & 1 << 1) != 0
        flags['bit_2'] = (binFlag & 1 << 2) != 0
        flags['bit_3'] = (binFlag & 1 << 3) != 0
        flags['bit_4'] = (binFlag & 1 << 4) != 0
        flags['bit_5'] = (binFlag & 1 << 5) != 0
        flags['bit_6'] = (binFlag & 1 << 6) != 0
        flags['bit_7'] = (binFlag & 1 << 7) != 0

        flags['userPresent'] = flags['bit_0']
        flags['userVerified'] = flags['bit_2']
        flags['attestedDataIncluded'] = flags['bit_6']
        flags['extensionDataIncluded'] = flags['bit_7']
        return flags

    '''
     * read attested data
     * @param string $binary
     * @param int $endOffset
     * @return \stdClass
     * @throws WebAuthnException
     '''
    def _readAttestData(self, binary, offset):
        attested_CData = {}
        end_offset = offset + 16
        if (len(binary) <= 55):
            raise WebAuthnException('Attested data should be present but is missing', ErrCodes.MISSING_ATTESTED_DATA)
        
        # The AAGUID of the authenticator (16 bytes)
        attested_CData.update({'aaguid':binary[37:end_offset]})

        end_offset = end_offset+2
        # Byte length L of Credential ID, 2 bytes unsigned big-endian integer.
        length = struct.unpack('>H', binary[53: end_offset])[0]
        end_offset = end_offset+length
        attested_CData.update({'credentialId': binary[55:end_offset]})
        # extract public key
        public_key, byte_reads = self._readCredentialPublicKey(binary, 55 + length)
        attested_CData.update({'credentialPublicKey':public_key})
        end_offset = end_offset + byte_reads 
        return (attested_CData, end_offset)

    '''
     * reads COSE key-encoded elliptic curve public key in EC2 format
     * @param string $binary
     * @param int $endOffset
     * @return \stdClass
     * @throws WebAuthnException
     '''
    def _readCredentialPublicKey(self, binary, offset):
        enc,end_offset = cbor.loads_in_place(binary[offset:])
        
        # print(enc)
        # COSE key-encoded elliptic curve public key in EC2 format
        credPKey = {}
        credPKey.update({'kty' : enc[self.COSE_KTY]})
        credPKey.update({'alg' : enc[self.COSE_ALG]})
        credPKey.update({'crv' : enc[self.COSE_CRV]})
        credPKey.update({'x'   : enc[self.COSE_X]})
        credPKey.update({'y'   : enc[self.COSE_Y]})
        # Validation
        if credPKey['kty'] != self.EC2_TYPE:
            raise WebAuthnException('public key not in EC2 format', ErrCodes.INVALID_PUBLIC_KEY)
        

        if credPKey['alg'] != self.EC2_ES256:
            raise WebAuthnException('signature algorithm not ES256', ErrCodes.INVALID_PUBLIC_KEY)

        if credPKey['crv'] != self.EC2_P256:
            raise WebAuthnException('curve not P-256', ErrCodes.INVALID_PUBLIC_KEY)
            

        if len(credPKey['x']) != 32:
            raise WebAuthnException('Invalid X-coordinate', ErrCodes.INVALID_PUBLIC_KEY)
            

        if len(credPKey['y']) != 32:
            raise WebAuthnException('Invalid Y-coordinate', ErrCodes.INVALID_PUBLIC_KEY)
            
        return (credPKey,end_offset)

    '''
     * reads cbor encoded extension data.
     * @param string $binary
     * @return array
     * @throws WebAuthnException
     '''
    def _readExtensionData(self, binary):
        ext = cbor.loads(binary)
        return ext


    # ---------------
    # DER functions
    # ---------------

    def _der_length(self, length):
        if length < 128:
            return bytes([length])
        lenBytes = b''
        while (length > 0):
            lenBytes = bytes(length % 256) + lenBytes
            length = length/256
        
        return bytes(0x80 | len(lenBytes)) + lenBytes

    def _der_sequence(self, contents):
        return b"\x30" + self._der_length(len(contents)) + contents

    def _der_oid(self, encoded):
        return b"\x06" + self._der_length(len(encoded)) + encoded

    def _der_bitString(self, bytes):
        return b"\x03" + self._der_length(len(bytes) + 1) + b"\x00" + bytes
