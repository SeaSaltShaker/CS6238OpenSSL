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
CName = "CertificateAuthority"

class CA:
    #TODO Make these objects private
    cakey = None
    cacert = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connections = []

    def __init__(self):
        #This first checks to see if the CA already has a certificate
        if(os.path.isfile('CA_Documents\\CA.pkey') & os.path.isfile('CA_Documents\\CA.cert')):
            with open("CA_Documents\\CA.pkey", 'r') as capk:
                #Decode the cakey
                print("The CA already has a private key.")
                self.cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, capk.read().encode('utf-8'))
            
            with open("CA_Documents\\CA.cert", 'r') as ca:
                #Decode the cacert
                print("The CA already has a certificate.")
                self.cacert = crypto.load_certificate(crypto.FILETYPE_PEM, ca.read().encode('utf-8'))
        #Otherwise, it generates them 
        else:
            #Generates public/private key
            self.cakey = crypto.PKey()
            self.cakey.generate_key(crypto.TYPE_RSA, 1028)
            #Generates request
            carequest = crypto.X509Req()
            subject = carequest.get_subject()
            setattr(subject, "CN", CName)
            carequest.set_pubkey(self.cakey)
            carequest.sign(self.cakey, "sha256")

            self.cacert = self.__createCertificate(carequest, (carequest, self.cakey), 0, (0, 60*60*24*365*5))

            with open(os.path.join(os.getcwd(), 'CA_Documents\\CA.pkey'), 'w+') as capk:
                capk.write(
                    crypto.dump_privatekey(crypto.FILETYPE_PEM, self.cakey).decode('utf-8')
                )

            with open(os.path.join(os.getcwd(), 'CA_Documents\\CA.cert'), 'w+') as ca:
                ca.write(
                    crypto.dump_certificate(crypto.FILETYPE_PEM, self.cacert).decode('utf-8')
                )

        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #Change for demo
        self.sock.bind(('192.168.56.1', 10000))
        self.sock.listen(1)

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
        cert = self.__createCertificate(request, (self.cacert, self.cakey), serial, (0, 60*60*24*365*5))
        with open(os.path.join(os.getcwd(), 'CA_Documents\\%s.cert' % (name,)), 'w+') as ca:
            ca.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
        return cert

    def handler(self, c, a):
        while True:
            try:
                data = c.recv(1024).decode("utf-8")
                command = data.split("|")
                print("Received " + data)
                #REQ [request] [requester's cname]
                if command[0] == "REQ":
                    print("Request: " + command[1])
                    cert = self.generateOutsideCert(command[1], serial, command[2])
                    c.send(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
                    self.dropClient(c)
                    return
                #AUTH [connection's cname]
                elif command[0] == "AUTH":
                    if(os.path.isfile("CA_Documents\\%s.cert" % (command[1],))):
                        with open("CA_Documents\\%s.cert" % (command[1],), 'r') as new_cert:
                            #Return the user's certificate
                            print("%s already has a certificate." % (command[1],))
                            c.send(crypto.load_certificate(crypto.FILETYPE_PEM, new_cert).encode('utf-8'))
                    else:
                        c.send("USER NOT FOUND")
            except SSL.ZeroReturnError:
                self.dropClient(c)
            except SSL.Error as errors:
                self.dropClient(c, errors)

    def dropClient(self, c, errors=None):
        if errors:
            print('Client %s left unexpectedly:' % (c,))
            print('  ', errors)
        else:
            print('Client %s left politely' % (c,))
        c.close()

    def run(self):
        print("Waiting for commands")
        while True:
            c, a = self.sock.accept()
            #Attaches the new connection to the handler method,
            #which parses whatever input it receives
            cThread = threading.Thread(target=self.handler, args=(c,a))
            cThread.daemon = True
            cThread.start()
            self.connections.append(c)
            print(self.connections)

auth = CA()
auth.run()