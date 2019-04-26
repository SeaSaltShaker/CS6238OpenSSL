from OpenSSL import SSL, crypto
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import socket
import sys
import threading
import base64

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
        self.sock.connect((address, 10003))
        #Authenticate the server
        serverName = self.sock.recv(1024).decode("utf-8")
        signature = self.sock.recv(1024)
        if(self.authenticate(serverName, signature) == False):
        #If not Authenticate
        #Close connection   
            self.sock.send(bytes("ERROR CANNOT AUTHENTICATE", 'utf-8')) 
            self.sock.close()
            sys.exit(0)
        else:
            self.sock.send(bytes("SERVER OK", 'utf-8'))
        #Authenticate ourselves
        self.sock.send(bytes(CName, 'utf-8'))
        self.sock.send(crypto.sign(self.pk, bytes(CName, 'utf-8'), "sha256"))
        if(self.sock.recv(1024).decode('utf-8').split()[0] != "CLIENT"):
            print("AUTH ERROR")
            sys.exit(0)

        self.userLogin()

        iThread = threading.Thread(target=self.sendMsg)
        iThread.daemon = True
        iThread.start()

        while True:
            data = self.sock.recv(1024)
            if not data:
                pass
            else:
                print(data.decode('utf-8'))

    def userLogin(self):
        #TODO start the session by sending the server the username
        #and the username encryped with the user's private key
        self.username = input("Please enter a username ")
        self.requestCert(self.username)
        print("Certificate acquired for %s!" %(self.username,))
        encryptedUsername = crypto.sign(self.user_pk, bytes(self.username, 'utf-8'), "sha256")
        self.sock.send(bytes(self.username, 'utf-8'))
        self.sock.send(encryptedUsername)
        response = self.sock.recv(1024).decode("utf-8")
        if(response.split()[0] == 'ERROR'):
            print(response)
            sys.exit(0)
        return

    def authenticate(self, authName, encryptedName):
        CAsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        CAsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        CAsock.connect(('192.168.56.1', 10000))
        print("Attempting to authenticate " + authName)
        CAsock.send(bytes("AUTH|" + authName, 'utf-8'))
        response = CAsock.recv(1024).decode('utf-8')
        
        #Check to see if the user/client already has a certificate
        if(response.split()[0] == "ERROR"):
            print(response)
            return False
        #Load the certificate
        userCert = crypto.load_certificate(crypto.FILETYPE_PEM, response)
        CAsock.close()
        try:
            crypto.verify(userCert, encryptedName, bytes(authName, "utf-8"), "sha256")
            print("Valid signature!")
            return True
        except Exception:
            print("Invalid signature")
            return False
        

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
        CAsock.close()
        #Check to see if the CA returned an error
        if(cert.decode("utf-8").split()[0] == "ERROR"):
            print(cert.decode("utf-8"))
            return
        with open(os.path.join(os.getcwd(), 'Client_Documents\\%s.cert' %(name,)), 'w+') as mycert:
            mycert.write(cert.decode('utf-8'))
        

    def disconnect(self):
        pass

    def verify_cb(self, conn, cert, errnum, depth, ok):
        certsubject = crypto.X509Name(cert.get_subject())
        commonname = certsubject.commonName
        print('Got certificate: ' + commonname)
        return ok

    def receiveData(self, DID):
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2)
        ctx.set_options(SSL.OP_NO_SSLv3)
        ctx.set_verify(
            SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verify_cb
        )  # Demand a certificate
        ctx.use_privatekey_file(os.path.join(dir, 'Client_Documents\\%s.pkey' %(CName,)))
        ctx.use_certificate_file(os.path.join(dir, 'Client_Documents\\%s.cert' %(CName,)))
        ctx.load_verify_locations(os.path.join(dir, 'Client_Documents\\CA.cert'))

        # Set up secure channel
        data_connection = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        data_connection.bind(('', 10004))
        with open('Client_Documents\\%s' %(DID,), 'r') as f:
            while True:
                data = f.read(1024)
                if not data: break
                data_connection.send(data.encode('utf-8'))
            f.close()
        data_connection.close()

    def sendData(self, DID):
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2)
        ctx.set_options(SSL.OP_NO_SSLv3)
        ctx.set_verify(
            SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verify_cb
        )  # Demand a certificate
        ctx.use_privatekey_file(os.path.join(dir, 'Client_Documents\\%s.pkey' %(CName,)))
        ctx.use_certificate_file(os.path.join(dir, 'Client_Documents\\%s.cert' %(CName,)))
        ctx.load_verify_locations(os.path.join(dir, 'Client_Documents\\CA.cert'))

        # Set up secure channel
        data_connection = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        data_connection.bind(('', 10004))
        with open('Client_Documents\\%s' %(DID,), 'w') as f:
            while True:
                data = data_connection.recv(1024).decode("utf-8")
                if not data: break
                f.write(data)
            f.close()
        data_connection.close()

    def sendMsg(self):
        while True:
            msg = input("Command: ")
            if(msg.split()[0].lower() == "help"):
                print("Usage:\nq, quit to log out\nckout [DID] to request a document\nckin [DID] [FLAG] to submit a document\ngrant [DID] [UNAME] [TIME] to change permissions\ndelete [DID] to delete a document")
            elif(msg.split()[0].lower() == "ckin"):
                DID = msg.split()[1]
                self.sock.send(bytes(msg, 'utf-8'))
                self.sock.send(crypto.sign(self.pk, bytes(msg, 'utf-8'), "sha256"))
                self.sendData(DID)                
            else:
                #Sign every message
                self.sock.send(bytes(msg, 'utf-8'))
                self.sock.send(crypto.sign(self.pk, bytes(msg, 'utf-8'), "sha256"))

#TODO pass the client's name and server address as parameters
#Usage client.py [address] [clientName]
#CName = sys.argv[2]
client = Client(socket.gethostbyname(socket.gethostname()))       
#client = Client(sys.argv[1])
