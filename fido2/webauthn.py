import hashlib, json
from urllib.parse import urlparse

from fido2.attestation_object import AttestationObject
from fido2.authenticator_data import AuthenticatorData
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends.openssl.hashes import hashes
from cryptography.exceptions import InvalidSignature

def _checkOrigin(rpId, origin):
    origin_parser = urlparse(origin)
    if rpId != 'localhost' and origin_parser.scheme != 'https':
        return False
    if rpId.lower() != origin_parser.hostname.lower():
        return False
    return True

def verify_register(rpId, clientDataJSON, attestationObject, challenge, 
                    requireUserVerification=False, requireUserPresent=True):

    client_data = json.loads(clientDataJSON)

    if 'challenge' not in client_data or challenge != client_data['challenge']:
        return None

    if 'type' not in client_data or client_data['type'] != 'webauthn.create':
        return None

    if 'origin' not in client_data or not _checkOrigin(rpId, client_data['origin']):
        return None

    att = AttestationObject(attestationObject)
    m = hashlib.sha256()
    m.update(rpId.encode('ascii'))
    hash_data = m.digest()
    if not att.validateRpIdHash(hash_data):
        return None

    m = hashlib.sha256()
    m.update(clientDataJSON.encode('ascii'))
    hash_data = m.digest()
    verify = att.validateAttestation(hash_data)
    if not verify:
        return None
    
    if requireUserPresent and not att.getAuthenticatorData().getUserPresent():
        return None
    
    if requireUserVerification and not att.getAuthenticatorData().getUserVerified():
        return None

    ret = {
        'rp_id':rpId,
        'credential_id': att.getAuthenticatorData().getCredentialId(),
        'credential_public_key': att.getAuthenticatorData().getPublicKeyPem(),
        'certificate': att.getCertificatePem(),
        'certificate_issuer':att.getCertificateIssuer(),
        'certificate_subject':att.getCertificateSubject(),
        'AAGUID':att.getAuthenticatorData().getAAGUID()
    }
    return ret

def verify_login(rpId, clientDataJSON, authenticatorData, signature, certificate, 
                challenge, requireUserVerification=False, requireUserPresent=True):

    client_data = json.loads(clientDataJSON)
    if 'type' not in client_data or client_data['type'] != 'webauthn.get':
        return False
    
    if 'challenge' not in client_data or challenge != client_data['challenge']:
        return False

    if 'origin' not in client_data or not _checkOrigin(rpId, client_data['origin']):
        return None

    authenticator_data = AuthenticatorData(authenticatorData)
    m = hashlib.sha256()
    m.update(rpId.encode('ascii'))
    rp_id_hash = m.digest()

    if authenticator_data.getRpIdHash() != rp_id_hash:
        return False

    if requireUserPresent and not authenticator_data.getUserPresent():
        return False
    
    if requireUserVerification and not authenticator_data.getUserVerified():
        return False

    m = hashlib.sha256()
    m.update(clientDataJSON.encode('ascii'))
    client_data_json_hash = m.digest()

    cert = x509.load_pem_x509_certificate(certificate, default_backend())
    public_key = cert.public_key()

    verify_data = authenticatorData + client_data_json_hash
    try:
        public_key.verify(signature, verify_data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        raise e