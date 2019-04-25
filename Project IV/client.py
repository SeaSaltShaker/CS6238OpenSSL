from OpenSSL import SSL, crypto
import os
import socket
import sys
import threading

os.chdir(sys.path[0])
CName = "3S_Client"

class Client:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    username = None

    def __init__(self, address):
        self.requestCert(CName)
        print("Certificate acquired for this client!")
        self.username = input("Please enter a username ")
        self.requestCert(self.username)
        print("Certificate acquired for %s!" %(self.username,))
        self.sock.connect((address, 10000))

        iThread = threading.Thread(target=self.sendMsg)
        iThread.daemon = True
        iThread.start()

        while True:
            data = self.sock.recv(1024)
            if not data:
                break
            print(data)

    def requestCert(self, name):
        #First we need to check to see if there is already a certificate
        if os.path.isfile('Client_Documents\\%s.cert' % (name,)):
            print("We already have a certificate for " + name)

        CAsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        CAsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        CAsock.connect(('192.168.56.1', 10000))
        #generate key pair
        pk = crypto.PKey()
        pk.generate_key(crypto.TYPE_RSA, 1028)
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
        with open(os.path.join(os.getcwd(), 'Client_Documents\\%s.cert' %(name,)), 'w+') as mycert:
            mycert.write(cert.decode('utf-8'))

    def disconnect(self):
        pass

    def sendMsg(self):
        msg = input("Command: ")
        self.sock.send(bytes(msg, 'utf-8'))

client = Client(socket.gethostbyname(socket.gethostname()))       
#client = Client(sys.argv[1])
