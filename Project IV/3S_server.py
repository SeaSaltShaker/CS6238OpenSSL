from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography
import threading
import socket
import sys
import os

nextDID = 1
didPermissions = {}
#key = CName, value = true/false (true means authenticated)
connectionPermissions = {}
CName = "3S_Server"
os.chdir(sys.path[0])

#print(SSL._CERTIFICATE_PATH_LOCATIONS)
class Server:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connections = []
    def __init__(self):
        self.requestCert()
        print("Certificate acquired!")
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  #this is the socket for the client
        self.sock.bind(('0.0.0.0', 10003))
        self.sock.listen(1)

    def handler(self, c, a):
        print("Accepted new connection")
        #Authenticate
        userName = c.recv(1024).decode('utf-8', 'ignore').split("|")
        
        if(self.authenticate(userName[0], userName[1]) == False):
        #If not Authenticate
        #Close connection    
            c.close()
            return
        userName = userName[0]
        while True:
            #TODO add the try/except block
            try:
                data = c.recv(1024).decode('utf-8')
                command = data.split()
                if command[0].lower() == "q" | command[0].lower() == "quit":
                    #End session. Update documents before closing
                    c.close()
                    return
                elif command[0].lower() == "ckout":
                    #Call checkout function
                    pass
                elif command[0].lower() == "ckin":
                    #call checkin function
                    pass
                elif command[0].lower() == "grant":
                    #call grant function
                    pass
                elif command[0].lower() == "delete":
                    #call delete function
                    pass
            except SSL.ZeroReturnError:
                #self.dropClient(c)
                c.close()
            except SSL.Error as errors:
                #self.dropClient(c, errors)
                c.close()

    def requestCert(self):
        #First we need to check to see if there is already a certificate
        if os.path.isfile('Server_Documents\\server.cert') & os.path.isfile('Server_Documents\\server.pkey'):
            print("We already have a certificate and private key for the server")
            #Loads the private key of the server
            with open('Server_Documents\\server.pkey', 'r') as mypk:
                self.pk = crypto.load_privatekey(crypto.FILETYPE_PEM, mypk.read().encode('utf-8'))
            return
        
        CAsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   #socekt for CA communication
        CAsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        CAsock.connect(('192.168.56.1', 10000))
        #generate key pair
        pk = crypto.PKey()
        pk.generate_key(crypto.TYPE_RSA, 1028)
        with open(os.path.join(os.getcwd(), 'Server_Documents\\server.pkey'), 'w+') as mypk:
            mypk.write(
                    crypto.dump_privatekey(crypto.FILETYPE_PEM, pk).decode('utf-8')
            )

        request = crypto.X509Req()
        subject = request.get_subject()

        setattr(subject, "CN", CName)

        request.set_pubkey(pk)
        request.sign(pk, "sha256")

        CAsock.send(bytes("REQ|" + crypto.dump_certificate_request(crypto.FILETYPE_PEM, request).decode('utf-8') + "|" +  CName, 'utf-8'))
        cert = CAsock.recv(1024)

        #Check to see if the CA returned an error
        if(cert.decode("utf-8").split()[0] == "ERROR"):
            print(cert.decode("utf-8"))
            return

        with open(os.path.join(os.getcwd(), 'Server_Documents\\server.cert'), 'w+') as mycert:
            mycert.write(cert.decode('utf-8'))

    def authenticate(self, authName, encryptedName):
        CAsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        CAsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        CAsock.connect(('192.168.56.1', 10000))
        print("Attempting to authenticate " + authName + " with signature " + encryptedName)
        CAsock.send(bytes("AUTH|" + authName, 'utf-8'))
        response = CAsock.recv(1024).decode('utf-8')
        #Check to see if the user/client already has a certificate
        if(response.split()[0] == "ERROR"):
            print(response)
            return False
        #Load the certificate
        userCert = crypto.load_certificate(crypto.FILETYPE_PEM, response)
        #Get the public_key
        user_pubkey = userCert.get_pubkey().to_cryptography_key()
        try:
            user_pubkey.verify(bytes(encryptedName, 'utf-8'), bytes(authName, 'utf-8'), padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except cryptography.exceptions.InvalidSignature:
            print("Invalid signature")
            return False

    def run(self):
        while True:
            c, a = self.sock.accept()
            cThread = threading.Thread(target=self.handler, args=(c,a))
            cThread.daemon = True
            cThread.start()
            self.connections.append(c)
            print(self.connections)

server = Server()
server.run()