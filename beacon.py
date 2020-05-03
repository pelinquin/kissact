#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" Usage: './beacon.py'  -> run the backend
'./beacon.py 5000' -> run a phone & './beacon.py 5001' -> run another phone
 hit 'u' key -> run upload, 'd' key -> run download, 'g' key -> run stop/go
"""

import socket, threading, secrets, dbm, ecc, http.server, socketserver, urllib, requests, re

BASP = 5000        # Base port number
MAXC = 10          # Max contacts
HOST = '127.0.0.1' # IP
TICK = 1           # in seconds
EPOC = 10          # in ticks
PORT = 8000        # backend port
URLB = 'http://%s:%d' %(HOST, PORT)         

class beacon:
    ear, say, go = {}, {}, False
    def __init__(self, arg):
        self.p, s = int(arg), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        threading.Thread(target=self.server).start()
        threading.Thread(target=self.client).start()
        while (True):
            c = input()
            if   c == "u": self.upload()   # hit u -> run upload 
            elif c == "d": self.download() # hit d -> run download
            elif c == "g": self.stopgo()   # hit g -> run stop/go
            elif c == "s": self.status()   # hit g -> run stop/go

    def status(self):
        exposed = {}
        if ecc.os.path.isfile('db/e%s' % self.p):
            with dbm.open('db/e%s' % self.p) as b:
                for x in b.keys(): exposed[x] = True
            with dbm.open('db/h%s' % self.p) as b:
                for x in [y for y in b.keys() if y in exposed]: print('risk')

    def stopgo(self):
        print ("go/stop")
        self.go = not self.go
            
    def client(self):
        arg, s = '%d' % self.p, socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        m, n, i = arg.encode('UTF-8') + secrets.token_bytes(12), now(), 0
        with dbm.open('db/s%s' % self.p, 'c') as b: # said ids
            while (True):
                if self.go and (now() - n >= TICK):
                    n, i = now(), i + 1
                    if not i%EPOC:
                        m = arg.encode('UTF-8') + secrets.token_bytes(12)
                        self.dump(b)
                    z = self.say[m]+1 if m in self.say else 0
                    self.say[m], b[m] = z, ecc.i2b(i, 4) + ecc.i2b(z, 4)                        
                    for x in [y for y in range(MAXC) if self.p!=BASP+y]: s.sendto(m, (HOST, BASP+x))
                    
    def dump(self, b):
        f = open('db/d%s' % self.p, 'bw')
        for i in b.keys(): f.write(i) #f.write('%s %s\n' %(i, b[i]))
        f.close()
                                
    def server(self):
        s, n, buf = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), now(), {}
        s.bind((HOST, self.p))
        while (True):
            m = s.recvfrom(1024)[0]
            if now() - n <= 4: buf[m] = True
            else: n, buf = now(), {}
            z = self.ear[m]+1 if m in self.ear else 0
            print (m, z, len(buf))
            with dbm.open('db/h%s' % self.p, 'c') as b: # heard ids
                self.ear[m], b[m] = z, ecc.i2b(now(), 4) + ecc.i2b(z, 4)

    def upload(self):
        print ('Upload to backend')
        r = requests.post(URLB, files = {'file': open("db/d%s" % self.p, "rb")})

    def download(self):
        if ecc.os.path.isfile('backend'):
            print ('Download backend update')
            r = requests.get(URLB, stream=True)
            with open('db/e%s' % self.p, 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024): 
                    if chunk: f.write(chunk)
        else: print ('no backend yet')

class handler(http.server.BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_POST(self):
        length = int(self.headers['Content-Length']) 
        data, j, beg = self.rfile.read(length), 0, False
        for i in range(length):
            if data[i:i+4] == b'\r\n\r\n': j, beg = i+4, True
            if beg and data[i:i+2] == b'--': break
        with dbm.open('backend', 'c') as b:
            for x in range((i-j)//16): b[data[j+16*x:j+16*(x+1)]] = b''
        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

    def do_GET(self):
        self._set_response()
        with open('backend', mode='rb') as f: self.wfile.write(f.read())

def backend():
    print(__doc__, "serving at port", PORT)
    socketserver.TCPServer((HOST, PORT), handler).serve_forever()

def now():
    return int(ecc.time.mktime(ecc.time.gmtime()))

if __name__ == '__main__':
    if not ecc.os.path.exists('db'): ecc.os.makedirs('db')        
    if len(ecc.sys.argv) == 2: b = beacon(ecc.sys.argv[1])
    else: threading.Thread(target=backend).start()
        
# End ⊔net!
