import cryptography
from OpenSSL import SSL
from OpenSSL import crypto
import os

"""
Adapted from PyOpenSSL's repository
https://github.com/pyca/pyopenssl/tree/master/examples
"""
class CA:
    cakey = None
    cacert = None
    carequest = None

    if(os.path.isfile('CA_Documents/CA.pkey') & os.path.isfile('CA_Documents/CA.cert')):
        with open("CA_Documents/CA.pkey", 'r') as capk:
            #Decode the cakey
            cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, capk.readline().encode('utf-8'))
        
        with open("CA_Documents/CA.cert", 'r') as ca:
            #Decode the cakey
            cacert = crypto.load_privatekey(crypto.FILETYPE_PEM, ca.readline().encode('utf-8'))
        
    else:
        cakey = __createKeyPair()
        carequest = __createCertRequest(cakey, CN="Certificate Authority")
        cacert = __createCertificate(carequest, (carequest, cakey), 0, (0, 60*60*24*365*5))

        with open("CA_Documents/CA.pkey", 'w') as capk:
            capk.write(
                crypto.dump_privatekey(crypto.FILETYPE_PEM, cakey).decode('utf-8')
            )

        with open("CA_Documents/CA.cert", 'w') as ca:
            ca.write(
                crypto.dump_certificate(crypto.FILETYPE_PEM, cacert).decode('utf-8')
            )

    def __createKeyPair(self):
        #initialize 
        pk = crypto.PKey()
        pk.generate_key(crypto.TYPE_RSA, 256)
        return pk

    def __createCertRequest(self, pk, digest="sha256", **name):
        #X509 is the standard for defining certificates
        request = crypto.X509Req()
        subject = request.get_subject()

        for key, value in name.items():
            setattr(subject, key, value)

        request.set_pubkey(pk)
        request.sign(pk, digest)
        return request

    def __createCertificate(self, req, issuerCertKey, serial, validityPeriod,
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
