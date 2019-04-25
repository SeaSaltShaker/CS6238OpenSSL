import cryptography
from OpenSSL import SSL
from OpenSSL import crypto
import os, sys
import threading
import socket
import random

"""
Adapted from PyOpenSSL's repository
https://github.com/pyca/pyopenssl/tree/master/examples
"""
#os.chdir('Project IV')
os.chdir(sys.path[0])
serial = random.randint(1, 10001)

class CA:
    cakey = None
    cacert = None
    carequest = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connections = []
    #Initializing a dictionary to hold (CNAME, Certificate_location)
    certificates = {}

    def __init__(self):
        if(os.path.isfile('CA_Documents\\CA.pkey') & os.path.isfile('CA_Documents\\CA.cert')):
            with open("CA_Documents\\CA.pkey", 'r') as capk:
                #Decode the cakey
                print("The CA already has a private key.")
                cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, capk.read().encode('utf-8'))
            
            with open("CA_Documents\\CA.cert", 'r') as ca:
                #Decode the cacert
                print("The CA already has a certificate.")
                cacert = crypto.load_certificate(crypto.FILETYPE_PEM, ca.read().encode('utf-8'))
            
        else:
            cakey = self.__createKeyPair()
            carequest = self.__createCertRequest(cakey, CN="Certificate Authority")
            cacert = self.__createCertificate(carequest, (carequest, cakey), 0, (0, 60*60*24*365*5))

            with open(os.path.join(os.getcwd(), 'CA_Documents\\CA.pkey'), 'w+') as capk:
                capk.write(
                    crypto.dump_privatekey(crypto.FILETYPE_PEM, cakey).decode('utf-8')
                )

            with open(os.path.join(os.getcwd(), 'CA_Documents\\CA.cert'), 'w+') as ca:
                ca.write(
                    crypto.dump_certificate(crypto.FILETYPE_PEM, cacert).decode('utf-8')
                )
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('192.168.56.1', 10000))
        self.sock.listen(1)

    def __createKeyPair(self):
        #initialize 
        pk = crypto.PKey()
        pk.generate_key(crypto.TYPE_RSA, 1028)
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
        serial += 1
        cert.gmtime_adj_notBefore(notBefore)
        cert.gmtime_adj_notAfter(notAfter)

        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(issuerKey, digest)
        return cert

    def generateOutsideCert(self, req, serial, name):
        request = crypto.load_certificate_request(crypto.FILETYPE_PEM, req)
        cert = self.__createCertificate(self, request, (self.cacert, self.cakey), serial, (0, 60*60*24*365*5))
        with open(os.path.join(os.getcwd(), 'CA_Documents\\%s.cert' % (name,)), 'w+') as ca:
            ca.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
        return cert

    def handler(self, c, a):
        while True:
            data = c.recv(1024)
            command = data.split(b"|")
            print("Received " + data.decode('utf-8'))
            if command[0] == "REQ":
                cert = self.generateOutsideCert(command[1], serial, command[3])
                c.send(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
                c.shutdown()
                c.close()
            elif command[0] == "AUTH":
                if(os.path.isfile("CA_Documents\\%s.pkey" % (command[3],))):
                    with open("CA_Documents\\%s.pkey" % (command[3],), 'r') as pk:
                        #Return the user's public key
                        print("The CA already has a private key.")
                        c.send(crypto.load_privatekey(crypto.FILETYPE_PEM, pk.read().encode('utf-8')))
                else:
                    c.send("USER NOT FOUND")

    def run(self):
        print("Waiting for commands")
        while True:
            c, a = self.sock.accept()
            cThread = threading.Thread(target=self.handler, args=(c,a))
            cThread.daemon = True
            cThread.start()
            self.connections.append(c)
            print(self.connections)

auth = CA()
auth.run()