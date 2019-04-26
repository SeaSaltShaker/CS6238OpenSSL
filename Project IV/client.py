from OpenSSL import SSL, crypto
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import socket
import sys
import threading

os.chdir(sys.path[0])
#TODO make the CName and the server address a parameter
CName = "3S_Client"

class Client:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    username = None
    pk = None
    user_pk = None

    def __init__(self, address):
        self.requestCert(CName)
        print("Certificate acquired for this client!")
        self.username = input("Please enter a username ")
        self.requestCert(self.username)
        print("Certificate acquired for %s!" %(self.username,))
        self.sock.connect((address, 10003))

        #TODO start the session by sending the server the username
        #and the username encryped with the user's private key
        authMessage = ""
        cryptoKey = self.user_pk.to_cryptography_key() #takes client's private key, which is in crypto.Pkey() and converts it to cryptography.RSAPrivateKey()
        #Signs the username using the private key of the user
        encryptedUsername = cryptoKey.sign(bytes(self.username, 'utf-8'), padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256() )
        authMessage = bytes(self.username + "|", 'utf-8') + encryptedUsername
        print(authMessage.decode('utf-8', "ignore"))
        self.sock.send(authMessage)

        iThread = threading.Thread(target=self.sendMsg)
        iThread.daemon = True
        iThread.start()

        while True:
            data = self.sock.recv(1024)
            if not data:
                pass
            else:
                print(data.decode('utf-8'))

    def requestCert(self, name):
        #First we need to check to see if there is already a certificate
        if os.path.isfile('Client_Documents\\%s.cert' % (name,)) & os.path.isfile('Client_Documents\\%s.pkey' % (name,)):
            print("We already have a certificate and private key for " + name)
            #Loads the private key of the client
            with open('Client_Documents\\%s.pkey' % (name,), 'r') as mypk:
                if(name == CName):
                    self.pk = crypto.load_privatekey(crypto.FILETYPE_PEM, mypk.read().encode('utf-8'))
                else:
                    self.user_pk = crypto.load_privatekey(crypto.FILETYPE_PEM, mypk.read().encode('utf-8'))
            return

        CAsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        CAsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        CAsock.connect(('192.168.56.1', 10000))
        #generate key pair
        pk = crypto.PKey()
        pk.generate_key(crypto.TYPE_RSA, 1028)
        if(name == CName):
            self.pk = pk
        else:
            self.user_pk = pk

        with open(os.path.join(os.getcwd(),'Client_Documents\\%s.pkey' % (name,)), 'w+') as mypk:
            mypk.write(
                    crypto.dump_privatekey(crypto.FILETYPE_PEM, pk).decode('utf-8')
            )

        request = crypto.X509Req()
        subject = request.get_subject()

        setattr(subject, "CN", name)

        request.set_pubkey(pk)
        request.sign(pk, "sha256")

        CAsock.send(bytes("REQ|" + crypto.dump_certificate_request(crypto.FILETYPE_PEM, request).decode('utf-8') + "|" +  name, 'utf-8'))
        cert = CAsock.recv(1024)
        #Check to see if the CA returned an error
        if(cert.decode("utf-8").split()[0] == "ERROR"):
            print(cert.decode("utf-8"))
            return
        with open(os.path.join(os.getcwd(), 'Client_Documents\\%s.cert' %(name,)), 'w+') as mycert:
            mycert.write(cert.decode('utf-8'))

    def disconnect(self):
        pass

    def sendMsg(self):
        msg = input("Command: ")
        self.sock.send(bytes(msg, 'utf-8'))

#TODO pass the client's name and server address as parameters
#Usage client.py [address] [clientName]
#CName = sys.argv[2]
client = Client(socket.gethostbyname(socket.gethostname()))       
#client = Client(sys.argv[1])
