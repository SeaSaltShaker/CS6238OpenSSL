
import socket
import sys
import threading

class Client:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    def __init__(self, address):
        self.sock.connect((address, 9999))

        iThread = threading.Thread(target=self.sendMsg)
        iThread.daemon = True
        iThread.start()

        while True:
            data = self.sock.recv(1024)
            if not data:
                break
            print(data)

    def sendMsg(self):
        self.sock.send(bytes(input(""), 'utf-8'))
        
client = Client(sys.argv[1])
