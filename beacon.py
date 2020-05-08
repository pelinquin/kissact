#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" Usage: './beacon.py' -> run the backend
'./beacon.py 5000' -> run a phone & './beacon.py 5001' -> run another phone
use ./doctor.py to generate codekey for covid+ person
 'u'key->update | 'g'key->stop/go | codekey->upload_ids | decimal->pay 
dcodekey: "24digit-code doc_email user_email" 
https://github.com/pelinquin/kissact
"""

import socket, threading, secrets, dbm, ecc, http.server, socketserver, urllib, requests, re, random

BASP = 5000        # Base port number
MAXC = 10          # Max simultaneous contacts
MCTS = 200         # Max historical contact allowed to upload after test
HOST = '127.0.0.1' # IP
TICK = 1           # in seconds
EPOC = 10          # in ticks
PORT = 8000        # backend port
MINF = 100         # max number of infected people
URLB = 'http://%s:%d' %(HOST, PORT)         

class beacon:
    ear, say, cts, go, current, k, price, balance = {}, {}, {}, False, None, ecc.ecdsa(), 0, 0
    def __init__(s, arg):
        s.p = int(arg)
        if not ecc.os.path.exists('db%d'%s.p): ecc.os.makedirs('db%d'%s.p)        
        threading.Thread(target=s.server).start()
        threading.Thread(target=s.client).start()
        s.k.generate()
        while (True):
            c = input()
            if   c == "u": s.update()                          # -> download from backend
            elif c == "g": s.stopgo()                          # -> stop/go
            elif c == "s" and s.go == False: print(s.status()) # -> display status if stop
            elif reg(re.match('^(\d\d)$', c)): s.pay(c)
            elif len(c) > 24 and len(c) < 90: s.update(c)      # -> try upload to backend
            else: print('command not valid')

    def pay(s, c):
        s.price = int(c)
        print ('PAY:%d' % s.price)
            
    def status(s):
        exposed = {}
        print ('Balance %d' % s.balance)
        if ecc.os.path.isfile('db%d/exposed'%s.p):
            with dbm.open('db%d/exposed'%s.p) as b:
                for x in b.keys(): exposed[x] = (datdecode(b[x][:4]), ecc.b2i(b[x][-1:]))
            with dbm.open('db%d/hear'%s.p) as b:
                for x in [y for y in b.keys() if y in exposed]:
                    return 'risk level %s %d' % (exposed[x][0], exposed[x][1])
        return 'ok'

    def stopgo(s):
        print ("go/stop")
        s.go = not s.go

    def getid(s, phone, dest):
        if s.price>0:
            print ('PAYED %d to %s' % (s.price, dest))
            s.balance -= s.price
        return ecc.i2b(phone%256) + secrets.token_bytes(10) + dest + ecc.i2b(s.price)
        
    def client(s):
        m, n, i = s.getid(s.p, ecc.i2b(0, 4)), now(), 0
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with dbm.open('db%d/say'%s.p, 'c') as b: # said ids
            while (True):
                if s.go and (now() - n >= TICK):
                    n, i = now(), i + 1
                    if s.price > 0: i = 0
                    if not i % EPOC:
                        dest = ecc.i2b(0, 4)
                        if s.current in s.cts: dest = s.cts[s.current][1:5]
                        m = s.getid(s.p, dest)
                        s.price = 0
                        s.dump(b)
                    z = s.say[m]+1 if m in s.say else 0
                    # lattitude/longitude if captured (data stay on the phone!)
                    lt, lo = ecc.i2b(random.randint(0, 100), 2), ecc.i2b(random.randint(0, 100), 2)
                    s.say[m], b[m] = z, ecc.i2b(n, 4) + ecc.i2b(z, 4) + lt + lo
                    s.current = m
                    for x in [y for y in range(MAXC) if s.p!=BASP+y]: t.sendto(m, (HOST, BASP+x))
                    
    def dump(s, b):
        f = open('db%d/dump'%s.p, 'bw') 
        for i in b.keys(): f.write(i) # contacts
        for c in s.cts: f.write(c[:-1] + ecc.i2b(ecc.b2i(c[-1:]) + 0x10)) # contacts-contacts
        f.close()

    def short(s, m):
        if m and len(m)>6: return m[:2] + m[-4:]
        return m
                                
    def server(s):
        t, n, buf, sdest = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), now(), {}, ecc.i2b(0, 4)
        t.bind((HOST, s.p))
        while (True):
            m = t.recvfrom(1024)[0]
            if now() - n <= 4: buf[m] = True
            else: n, buf = now(), {}
            z, dest, price = s.ear[m]+1 if m in s.ear else 0, m[-5:-1], ecc.b2i(m[-1:])
            if s.current: s.cts[s.current] = m
            print (len(s.cts), s.short(m), z, len(buf), s.short(s.current))
            if price > 0 and sdest != dest:
                print ('RECEIVE %d' % price)
                s.balance += price
                sdest = dest                
            with dbm.open('db%d/hear'%s.p, 'c') as b: # heard ids
                s.ear[m], b[m] = z, ecc.i2b(now(), 4) + ecc.i2b(z, 4) 

    def update(s, c=''):
        if c == '':
            print ('Update from backend')
            r = requests.post(URLB)
        else:
            print ('Try to upload to backend with code\n%s' %c)
            r = requests.post(URLB, files = {'file': open("db%d/dump"%s.p, "rb")}, data = {'c': c})
        with open('db%d/exposed'%s.p, 'wb') as f:
            for chk in r.iter_content(chunk_size=1024): 
                if chk: f.write(chk)

class handler(http.server.BaseHTTPRequestHandler):
    def extract(s, d):
        b = False
        for i in range(len(d)):
            if d[i:i+4] == b'\r\n\r\n': j, b = i+4, True
            if b and d[i:i+4] == b'\r\n--': return (d[j:i], i) 
        return (b'', 0)

    def response(s):
        s.send_response(200)
        s.send_header('Content-type', 'text/plain')
        s.end_headers()
        
    def do_POST(s):
        data = s.rfile.read(int(s.headers['Content-Length']))
        (code, pos) = s.extract(data)
        (ids, pos)  = s.extract(data[pos:])
        if len(data) > 0 and len(code)>0 and len(code)<90 and len(ids)>0:
            if reg(re.match('^\s*(\S{24})\s+(\S+@\S+)\s+(\S+@\S+)\s*$', code.decode('utf-8'))):
                k = reg.v.group(1).encode('utf-8')
                d, p = reg.v.group(2).encode('utf-8'), reg.v.group(3).encode('utf-8')
                with dbm.open('backend/keys', 'c') as b:
                    for x in b.keys():
                        if x == k and b[x] == d + b' ' + p:
                            b[x] = d
                            with dbm.open('backend/exposed', 'c') as bb:
                                for x in range(len(ids)//16):
                                    bb[ids[16*x:16*x+10]] = ids[16*x+10:16*(x+1)]
                            print ('backend server well updated with contacts')
        s.response()
        if ecc.os.path.isfile('backend/exposed'):
            with open('backend/exposed', mode='rb') as f: s.wfile.write(f.read())
        else:
            s.wfile.write(b'POST request ' + s.path.encode('utf-8'))

    def do_GET(s):
        s.response()
        s.wfile.write (b'BACKEND ' + s.path.encode('utf-8'))
        for f in ('backend/exposed', 'backend/keys'):
            if ecc.os.path.isfile(f):
                with dbm.open(f) as b:
                    s.wfile.write (b'\nFILE: ' + f.encode('utf-8'))
                    s.wfile.write (b': %d RECORDS' % len(b.keys()))
                    for i in b.keys():
                        s.wfile.write (b'\n%02d:%02d ' % (len(i), len(b[i])))
                        s.wfile.write (repr(i).encode('utf-8') + b' ' + repr(b[i]).encode('utf-8'))

class backend():
    root = secrets.token_bytes(16)
    def __init__(s):
        if not ecc.os.path.exists('backend'): ecc.os.makedirs('backend')        
        k = ecc.i2b(0, 16)
        if not ecc.os.path.exists('backend/keys'):
            with dbm.open('backend/keys', 'c') as b:
                for i in range(MINF):
                    k = ecc.hashlib.sha256(s.root + k).digest()[:16]
                    b[ecc.z56encode(k)] = b''
        print('Serving', URLB)
        socketserver.TCPServer((HOST, PORT), handler).serve_forever()
                
def now():
    return int(ecc.time.mktime(ecc.time.gmtime()))

def datdecode(t):
    return ecc.time.strftime('%d/%m/%y %H:%M:%S', ecc.time.localtime(float(ecc.b2i(t))))

def reg(v):
    reg.v = v
    return v

if __name__ == '__main__':
    if len(ecc.sys.argv) == 2: beacon(ecc.sys.argv[1])
    else: backend()
    print (__doc__)
        
# End ⊔net!
