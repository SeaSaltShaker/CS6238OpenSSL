import cryptography
from OpenSSL import SSL
from OpenSSL import crypto

"""
Adapted from PyOpenSSL's repository
https://github.com/pyca/pyopenssl/tree/master/examples
"""

def createKeyPair():
    pk = crypto.PKey()
    pk.generate_key(crypto.TYPE_RSA, 256)
    return pk

def createCertRequest(pk, digest="sha256", **name):
    #X509 is the standard for defining certificates
    request = crypto.X509Req()
    subject = request.get_subject()

    for key, value in name.items():
        setattr(subject, key, value)

    request.set_pubkey(pk)
    request.sign(pk, digest)
    return request

def createCertificate(req, issuerCertKey, serial, validityPeriod,
                        digest="sha256"):
    """
    Generate a certificate given a certificate request.
    Arguments: req        - Certificate request to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is sha256
    Returns:   The signed certificate in an X509 object
    """                  
    issuerCert, issuerKey = issuerCertKey
    notBefore, notAfter = validityPeriod
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)

    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert


