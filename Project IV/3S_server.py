from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
from Crypto import Random
import cryptography
import threading
import socket
import sys
import os
import struct
import base64
import datetime 

#{DID: (owner, securityFlag, {TargetUser: ('[I][O]', expirationDate}, [optional AES key])}
#TODO: Change this to a file, so we won't lose everything when the server is restarted
didPermissions = {}
CName = "3S_Server"
os.chdir(sys.path[0])
nextDID = 1

#print(SSL._CERTIFICATE_PATH_LOCATIONS)
class Server:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connections = []
    pk = None
    def __init__(self):
        self.requestCert()
        #Loads the current Dictionary permissions
        self.loadDID()
        print("Certificate acquired!")
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  #this is the socket for the client
        self.sock.bind(('0.0.0.0', 10003))
        self.sock.listen(1)

    def loadDID(self):
        global didPermissions
        with open("Server_Documents\\curDID.txt", "r") as f:
            didPermissions = eval(f.read())
            f.close()

    def updateDID(self):
        global didPermissions
        with open("Server_Documents\\curDID.txt", "w") as f:
            f.write(str(didPermissions))
            f.close()
        return nextDID


    def handler(self, c, a):
        print("Accepted new connection")
        #Authenticate ourselves
        c.send(bytes(CName, 'utf-8'))
        sign = crypto.sign(self.pk, bytes(CName, 'utf-8'), "sha256")
        c.send(sign)

        if(c.recv(1024).decode('utf-8').split()[0] != "SERVER"):
            print("AUTH ERROR")
            return
        
        #Authenticate this client
        clientName = c.recv(1024).decode("utf-8")
        signature = c.recv(1024)
        if(self.authenticate(clientName, clientName, signature) == False):
        #If not Authenticate
        #Close connection   
            c.send(bytes("ERROR CANNOT AUTHENTICATE THIS CLIENT", 'utf-8')) 
            c.close()
            return
        else:
            c.send(bytes("CLIENT OK", 'utf-8'))  
        #Authenticate the client's user. The client will always speak on the user's behalf   
        userName = c.recv(1024).decode("utf-8")
        signature = c.recv(1024)
        if(self.authenticate(userName, userName, signature) == False):
        #If not Authenticate
        #Close connection   
            c.send(bytes("ERROR CANNOT AUTHENTICATE", 'utf-8')) 
            c.close()
            return
        else:
            c.send(bytes("USER OK", 'utf-8'))

        while True:
            #TODO add the try/except block
            try:
                data = c.recv(1024).decode('utf-8')
                signature = c.recv(1024)
                #If the message can't be verified as being from the client, then don't do anything.
                if(self.authenticate(clientName, data, signature) == False):
                    continue
                command = data.split()
                if (command[0].lower() == "q") | (command[0].lower() == "quit"):
                    #End session. Update documents before closing
                    #TODO: if the client used ckout, then probe for ckin before quitting
                    c.close()
                    return
                #ckout [DID]
                elif command[0].lower() == "ckout":
                    self.checkout(command[1], userName, c)
                #ckin [did] [security flag] (C or I) [number_of_expected_bytes]
                elif command[0].lower() == "ckin":
                    self.checkin(command[1], command[2], command[3], userName, c)
                #grant [DID] [UNAME] [permissions] [TIME]
                elif command[0].lower() == "grant":
                    self.grant(command[1], command[2], command[3], command[4], userName)
                #delete [DID]
                elif command[0].lower() == "delete":
                    self.delete(command[1])
                    pass
            except SSL.ZeroReturnError:
                self.dropClient(c)
            except SSL.Error as errors:
                self.dropClient(c, errors)

    """Grants permissions by modifying the dictionary and changing permissions"""
    #{DID: (owner, securityFlag, {TargetUser: ('[I][O]', expirationDate)})}
    def grant(self, DID, UID, securityFlag, Time, userName):
        if DID in didPermissions.keys():
            if didPermissions[DID][0] == userName:
                didPermissions[DID][2][UID] = (securityFlag, datetime.datetime.now() + datetime.timedelta(minutes=int(Time)))
                self.updateDID()
            else:
                print("ERROR ACCESS DENIED")
        
    
    """Safe Delete of a file DID"""
    def delete(self, DID):
        pass #This command does nothing, but it's here so that it doesn't throw any errors

    def checkout(self, DID, userName, c):
        global didPermissions

        #{DID: (owner, securityFlag, {TargetUser: ('[I][O]', expirationDate)})}

        #First check to see if we already have this document
        if(DID in didPermissions.keys()):
            #Then check to see if the username is the owner:
            if(userName == didPermissions[DID][0]):
                pass
            #Otherwise the document has a different owner
            elif(userName in didPermissions[DID][2].keys()):
                pass
                #Then check to see if the user has checkin permissions
                if("O" in didPermissions[DID][2][userName][0] & datetime.datetime.now() > didPermissions[DID][2][userName][1]):
                    pass
                #Either this user does not have checkout access or their time has expired
                else:
                    return ("ERROR ACCESS DENIED")
            #Else if the owner said that all users can check out
            elif("ALL" in didPermissions[DID][2].keys()):
                if("O" in didPermissions[DID][2]["ALL"][0]):
                    pass
                else:
                    return ("ERROR ACCESS DENIED")
            #Otherwise, this user is not in the list of target users
            else:
                return ("ERROR ACCESS DENIED")
        #In this case, there is no document at all
        else:
            return ("ERROR ACCESS DENIED")

        #TODO: transfer the data from the server to the client
        if didPermissions[DID][1] == "C":
            self.sendData(DID, c, True)
        else:
            self.sendData(DID, c)

    def checkin(self, DID, securityFlag, num_bytes, userName, c):
        global didPermissions
        print("Checking in document " + DID)
        #{DID: (owner, securityFlag, {TargetUser: ('[I][O]', expirationDate)})}
        owner = None
        newDocument = False
        #First check to see if we already have this document
        if(DID in didPermissions.keys()):
            #Then check to see if the username is the owner:
            if(userName == didPermissions[DID][0]):
                owner = userName
            #Otherwise the document has a different owner
            elif(userName in didPermissions[DID][2].keys()):
                owner = didPermissions[DID][0]
                #Then check to see if the user has checkin permissions
                if(("I" in didPermissions[DID][2][userName][0]) & (datetime.datetime.now() < didPermissions[DID][2][userName][1])):
                    pass
                else:
                    return ("ERROR ACCESS DENIED")
            #Else if the owner said that all users can checkin
            elif("ALL" in didPermissions[DID][2].keys()):
                owner = didPermissions[DID][0]
                if("I" in didPermissions[DID][2]["ALL"][0]):
                    pass
                else:
                    owner = userName
                    newDocument = True
            #Otherwise, this non-associated user will overwrite the old one
            else:
                owner = userName
                newDocument = True
        #We will create a new document from scratch
        else:
            newDocument = True
            owner = userName

        key = None
        #TODO: transfer the data from the client to the server
        if(securityFlag.lower() == "c"):
            key = self.receiveData(DID, num_bytes, c, True)
        else:
            key = self.receiveData(DID, num_bytes, c)

        #Finally, replace the key if we are creating a new file.
        if(newDocument == True):
            if key != None:
                didPermissions[DID] = (owner, securityFlag.upper(), {}) + key
            else:
                didPermissions[DID] = (owner, securityFlag.upper(), {})
            #Update the DID file
            print("New owner: " + owner)
            self.updateDID()

    def generateAESKey(self):
        cryptoPk = self.pk.to_cryptography_key().public_key()
        #Generates a 32 byte random key
        AESKey = Random.new().read(32)
        print("Generate key")
        print(AESKey.decode(errors='ignore'))
        iv = ''.join(chr(0) for i in range(16))
        mode = AES.MODE_CBC
        encryptor = AES.new(AESKey, mode, iv.encode('utf-8'))
        """
        backend = default_backend()
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(0), backend=backend)
        encryptor = cipher.encryptor()"""
        return encryptor, (cryptoPk.encrypt(AESKey,padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),label=None)),)

    def returnAESKey(self, DID):
        global didPermissions
        cryptoPk = self.pk.to_cryptography_key()
        encryptedKey = didPermissions[DID][3]
        AESKey = cryptoPk.decrypt(encryptedKey, padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),label=None))
        return AESKey

    def verify_cb(self, conn, cert, errnum, depth, ok):
        certsubject = crypto.X509Name(cert.get_subject())
        commonname = certsubject.commonName
        print('Got certificate: ' + commonname)
        return ok

    def sendData(self, DID, c, confidential=False):
        acceptingSize = 1024
        #https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
        if(confidential == True):
            key = self.returnAESKey(DID)
            print("Sending Key")
            print(key.decode(errors='ignore'))
            with open('Server_Documents\\%s' %(DID,), 'rb') as f:
                origsize = struct.unpack('<Q', f.read(struct.calcsize('Q')))[0]
                origsize = int(origsize)
                #iv = f.read(16)
                iv = ''.join(chr(0) for i in range(16))
                decryptor = AES.new(key, AES.MODE_CBC, iv.encode('utf-8'))
                c.send(bytes(str(origsize), 'utf-8'))
                stri = c.recv(1024).decode('utf-8')
                print(stri)
                if(stri == "START"):
                    pass #flushes the thing...
                else:
                    print("FAILURE")
                sendSize = 0
                while sendSize < origsize:
                    chunk = f.read(acceptingSize)
                    if len(chunk) == 0:
                        break
                    data = decryptor.decrypt(chunk)
                    print(data.decode(errors='replace'))
                    c.send(data)
                    sendSize += acceptingSize
        else:
            with open('Server_Documents\\%s' %(DID,), 'r') as f:
                b = os.path.getsize("Server_Documents\\%s" %(DID,))
                c.send(bytes(b, 'utf-8'))
                c.recv(1024) #flushes the thing...
                while True:
                    data = f.read(acceptingSize)
                    if not data: 
                        break
                    c.send(data.encode('utf-8'))
                f.close()
            c.send("200".encode('utf-8'))

    def receiveData(self, DID, num_bytes, c, confidential=False):
        acceptedBytes = 0
        acceptingBytes = 1024
        num_bytes = int(num_bytes)

        #Then we need to pad using AES
        #https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
        if(confidential == True):
            encryptor, aesKey = self.generateAESKey()
            iv = ''.join(chr(0) for i in range(16))
            with open('Server_Documents\\%s' %(DID,), 'wb') as f:
                f.write(struct.pack('<Q', num_bytes))
                #f.write(iv.encode('utf-8'))

                while acceptedBytes < num_bytes:
                    print(acceptedBytes)
                    print (num_bytes)
                    if((num_bytes-acceptedBytes) < acceptingBytes):
                        acceptingBytes = num_bytes - acceptedBytes
                    chunk = c.recv(acceptingBytes).decode('utf-8')
                    if len(chunk) == 0:
                        break
                    #Padding the last block
                    elif len(chunk) % 16 != 0:
                        chunk += ' ' * (16 - len(chunk) % 16)
                    f.write(encryptor.encrypt(chunk.encode('utf-8')))
                    acceptedBytes += acceptingBytes
                f.close()
            print("Done saving file!")
            return aesKey
            
        
        else:
            with open('Server_Documents\\%s' %(DID,), 'w') as f:
                while acceptedBytes < num_bytes:
                    print(acceptedBytes)
                    print (num_bytes)
                    if((num_bytes-acceptedBytes) < acceptingBytes):
                        acceptingBytes = num_bytes - acceptedBytes
                    data = c.recv(acceptingBytes).decode("utf-8")
                    print(data)
                    f.write(data)
                    acceptedBytes += acceptingBytes
                f.close()
            return None

    def dropClient(self, c, errors=None):
        if errors:
            print('Client %s left unexpectedly:' % (c,))
            print('  ', errors)
        else:
            print('Client %s left politely' % (c,))
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
        self.pk = crypto.PKey()
        self.pk.generate_key(crypto.TYPE_RSA, 1028)
        with open(os.path.join(os.getcwd(), 'Server_Documents\\server.pkey'), 'w+') as mypk:
            mypk.write(
                    crypto.dump_privatekey(crypto.FILETYPE_PEM, self.pk).decode('utf-8')
            )

        request = crypto.X509Req()
        subject = request.get_subject()

        setattr(subject, "CN", CName)

        request.set_pubkey(self.pk)
        request.sign(self.pk, "sha256")

        CAsock.send(bytes("REQ|" + crypto.dump_certificate_request(crypto.FILETYPE_PEM, request).decode('utf-8') + "|" +  CName, 'utf-8'))
        cert = CAsock.recv(1024)
        CAsock.close()

        #Check to see if the CA returned an error
        if(cert.decode("utf-8").split()[0] == "ERROR"):
            print(cert.decode("utf-8"))
            return

        with open(os.path.join(os.getcwd(), 'Server_Documents\\server.cert'), 'w+') as mycert:
            mycert.write(cert.decode('utf-8'))

    def authenticate(self, authName, message, encryptedMessage):
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
            crypto.verify(userCert, encryptedMessage, bytes(message, "utf-8"), "sha256")
            print("Valid signature!")
            return True
        except Exception:
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