from OpenSSL import SSL, crypto
import threading
import socket
import sys
import os

nextDID = 1
didPermissions = {}
CName = "3S_Server"
os.chdir(sys.path[0])

#print(SSL._CERTIFICATE_PATH_LOCATIONS)
class Server:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connections = []
    def __init__(self):
        self.requestCert()
        print("Certificate acquired!")
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', 10000))
        self.sock.listen(1)

    def handler(self, c, a):
        while True:
            data = c.recv(1024)
            command = data.split()
            if command[0] == "REQ":
                pass

    def requestCert(self):
        CAsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        CAsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        CAsock.connect(('192.168.56.1', 10000))
        #generate key pair
        pk = crypto.PKey()
        pk.generate_key(crypto.TYPE_RSA, 1028)

        request = crypto.X509Req()
        subject = request.get_subject()

        setattr(subject, "CN", CName)

        request.set_pubkey(pk)
        request.sign(pk, "sha256")

        CAsock.send(bytes("REQ|" + crypto.dump_certificate_request(crypto.FILETYPE_PEM, request).decode('utf-8') + "|" +  CName, 'utf-8'))
        cert = CAsock.recv(1024)
        print(cert)
        if cert == "USER NOT FOUND":
            print(cert)
        else:
            with open(os.path.join(os.getcwd(), 'Server_Documents\\server.cert'), 'w+') as mycert:
                mycert.write(cert)


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