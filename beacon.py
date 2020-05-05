#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" Usage: './beacon.py'  -> run the backend
'./beacon.py 5000' -> run a phone & './beacon.py 5001' -> run another phone
use ./doctor.py to generate codekey for covid+ person
 'u' key -> update, 'g' key -> stop/go, codekey -> upload ids
https://github.com/pelinquin/kissact
"""

import socket, threading, secrets, dbm, ecc, http.server, socketserver, urllib, requests, re, random

BASP = 5000        # Base port number
MAXC = 10          # Max contacts
HOST = '127.0.0.1' # IP
TICK = 1           # in seconds
EPOC = 10          # in ticks
PORT = 8000        # backend port
MINF = 100         # max number of infected people
URLB = 'http://%s:%d' %(HOST, PORT)         

class beacon:
    ear, say, cts, go, current = {}, {}, {}, False, None
    def __init__(self, arg):
        self.p, s = int(arg), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        threading.Thread(target=self.server).start()
        threading.Thread(target=self.client).start()
        while (True):
            c = input()
            if   c == "u": self.update()                             # -> download
            elif c == "g": self.stopgo()                             # -> stop/go
            elif c == "s" and self.go == False: print(self.status()) # -> display status if stop
            elif len(c) > 24 and len(c) < 90: self.upload(c)         # -> try upload
            else: print('command not valid')

    def status(self):
        exposed = {}
        if ecc.os.path.isfile('db/e%s' % self.p):
            with dbm.open('db/e%s' % self.p) as b:
                for x in b.keys(): exposed[x] = ecc.b2i(b[x])
            with dbm.open('db/h%s' % self.p) as b:
                for x in [y for y in b.keys() if y in exposed]: return 'risk level %d' % exposed[x]
        return 'ok'

    def stopgo(self):
        print ("go/stop")
        self.go = not self.go
            
    def client(self):
        arg, s = '%d' % self.p, socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        m, n, i = arg.encode('utf-8') + secrets.token_bytes(12), now(), 0
        with dbm.open('db/s%s' % self.p, 'c') as b: # said ids
            while (True):
                if self.go and (now() - n >= TICK):
                    n, i = now(), i + 1
                    if not i%EPOC:
                        m = arg.encode('utf-8') + secrets.token_bytes(12)
                        self.dump(b, all=False)
                    z = self.say[m]+1 if m in self.say else 0
                    # lattitude/longitude if captured (data stay on the phone!)
                    lt, lo = ecc.i2b(random.randint(0, 1000), 2), ecc.i2b(random.randint(0, 1000), 2)
                    self.say[m], b[m] = z, ecc.i2b(i, 4) + ecc.i2b(z, 4) + lt + lo
                    self.current = m
                    for x in [y for y in range(MAXC) if self.p!=BASP+y]: s.sendto(m, (HOST, BASP+x))
                    
    def dump(self, b, all=True):
        f = open('db/d%s' % self.p, 'bw')
        for i in b.keys():
            if all:             f.write(i + ecc.i2b(1, 4)) # all ids
            elif i in self.cts: f.write(i + ecc.i2b(1, 4)) # only ids with contacts
        with dbm.open('db/h%s' % self.p, 'c') as bb:
            for i in bb.keys(): f.write(i + ecc.i2b(2, 4)) # second level contacts ids
        f.close()
                                
    def server(self):
        s, n, buf = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), now(), {}
        s.bind((HOST, self.p))
        while (True):
            m = s.recvfrom(1024)[0]
            if now() - n <= 4: buf[m] = True
            else: n, buf = now(), {}
            z = self.ear[m]+1 if m in self.ear else 0
            if self.current: self.cts[self.current] = m
            print (m, z, len(buf), self.current)
            with dbm.open('db/h%s' % self.p, 'c') as b: # heard ids
                self.ear[m], b[m] = z, ecc.i2b(now(), 4) + ecc.i2b(z, 4) 

    def upload(self, c):
        print ('Try to upload to backend with code\n%s' %c)
        r = requests.post(URLB, files = {'file': open("db/d%s" % self.p, "rb")}, data = {'c': c})

    def update(self):
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

    def extract(self, d):
        b = False
        for i in range(len(d)):
            if d[i:i+4] == b'\r\n\r\n': j, b = i+4, True
            if b and d[i:i+4] == b'\r\n--': return (d[j:i], i) 
        return (b'', 0)
        
    def do_POST(self):
        data = self.rfile.read(int(self.headers['Content-Length']))
        #open('log', 'bw').write(data)
        (code, pos) = self.extract(data)
        (ids, pos) = self.extract(data[pos:])
        if len(code)>0 and len(code)<90 and len(ids)>0:
            if reg(re.match('^\s*(\S{24})\s+(\S+@\S+)\s+(\S+@\S+)\s*$', code.decode('utf-8'))):
                k = reg.v.group(1).encode('utf-8')
                d, p = reg.v.group(2).encode('utf-8'), reg.v.group(3).encode('utf-8')
                with dbm.open('keys', 'c') as b:
                    for x in b.keys():
                        if x == k and b[x] == d + b' ' + p:
                            b[x] = d
                            with dbm.open('backend', 'c') as bb:
                                for x in range(len(ids)//20): bb[ids[20*x:20*x+16]] = ids[20*x+16:20*(x+1)]
                            print ('backend server well updated with your data')
        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

    def do_GET(self):
        self._set_response()
        with open('backend', mode='rb') as f: self.wfile.write(f.read())

class backend():
    root = secrets.token_bytes(16)
    def __init__(self):
        k = ecc.i2b(0, 16)
        if not ecc.os.path.exists('keys'):
            with dbm.open('keys', 'c') as b:
                for i in range(MINF):
                    k = ecc.hashlib.sha256(self.root + k).digest()[:16]
                    b[ecc.z56encode(k)] = b''
        threading.Thread(target=self.serve).start()
        print(__doc__, "serving at port", PORT)
        while (True):
            c = input()
            if c == 'i': print('Infected:%d' % self.nb())
            else: print('command not valid')
                
    def nb(self):
        if not ecc.os.path.exists('keys'): return 0
        with dbm.open('keys') as b:
            return sum([1 for x in b.keys() if len(b[x])>0])
                        
        
    def serve(self):
        socketserver.TCPServer((HOST, PORT), handler).serve_forever()

def now():
    return int(ecc.time.mktime(ecc.time.gmtime()))

def reg(v):
    reg.v = v
    return v

if __name__ == '__main__':
    if not ecc.os.path.exists('db'): ecc.os.makedirs('db')        
    if len(ecc.sys.argv) == 2: beacon(ecc.sys.argv[1])
    else: backend()
        
# End ⊔net!
