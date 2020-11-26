#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" 
  **** EHANCED SIGNATURE ****

 (with HTTP PUBLIC server)
USAGE: 
 './esig.py'       -> run Public (PUB)
 './esig.py Alice' -> run Alice's phone  
 './esig.py BoB'   -> run Bob's   phone
COMMANDS:
 i => init network (UDP ports)
 b => get balances
 t => get discret time cross values 
 d => local dadabase dump
 h => help
OPERATIONS:
 alice: '20bob'        => Alice pays (offline) 20 to Bob
 carOl: 'pUb 34 Alice' => Carol pays (online)  34 to Alice 
FORMAT: 
 message(13):src(4)+dst(4)val(3)nb(2)+sign(96) -> (109)
 (Production system uses 5 bytes ID length, not 4)
FORMAL:
 The economic system is represented by H, a Square Sparse Matrix of Humans-ID
 Definition: A cross is an application linking one position to 
  a function of the column and the raw of such position in H
 The time-cross    is the value: sum of column sum and raw sum
 The balance-cross is the value: diff between the column sum and raw sum
FAQ:
CONTACT: laurent.fournier@adox.io
"""

import socket, threading, ecc, re, dbm, http.server, socketserver, json, urllib, requests
BASP = 5000           # Base port number
MAXP = 10             # Max nb phones
DEBT = 100            # Self-debt limit
RLEN = 109            # Request len (message+signature)
HOST = '192.168.1.13' # local host
PURL = 'http://91.168.92.157:50001'
PORT = 50001          # PUB port
URLB = 'http://%s:%d' %(HOST, PORT)         

class node:
    def __init__(s, name):
        s.n, s.tbl, s.rvs, s.tid, s.tpk, s.pk = name, {}, {}, {}, {}, b''
        s.reset()
        threading.Thread(target=s.server).start()
        if s.n == 'PUB':
            threading.Thread(target=s.http, args=(s,)).start()
            print(requests.get(PURL).content.decode('utf-8')) # test http server
        while (True):
            c = input('%s>' % s.n)
            if   re.match('^\s*(I|INIT)\s*$',           c, re.I):  print (s.init())
            elif re.match('^\s*(H|HELP|DOC)\s*$',       c, re.I):  print (__doc__)
            elif re.match('^\s*(D|DUMP|DATA|BASE)\s*$', c, re.I):  s.readdb()
            elif re.match('^\s*(T|TIME)\s*$',           c, re.I):  print(s.times())
            elif re.match('^\s*(B|BAL|BALANCE)\s*$',    c, re.I):  print(s.bals())
            elif reg(re.match('^\s*(|P|PUB)\s*(\d+)\s*([A-Z]+)\s*$', c, re.I)): s.commit(reg)
            elif c.upper() in s.tid: s.chat(c.upper())
            else: print('Command not found')

    def init(s):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for x in range(MAXP): t.sendto(b'who?', (HOST, BASP+x))
        t.settimeout(1)
        while (True):
            try:
                m, a = t.recvfrom(1024)
                name = m[48:].decode('utf-8')
                s.tbl[name], s.tid[name], s.tpk[m[:4]], s.rvs[m[:4]] = a[1], m[:4], m[4:48], name
            except: break
        t.settimeout(None)
        s.savepks()
        return s.tbl
    
    def commit(s, r):
        t, k = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), ecc.ecdsa()
        isn, val, rcp = (r.v.group(1) != 'PUB'), int(r.v.group(2)), r.v.group(3).upper()
        if s.check(s.tid[s.n], val) == False: return
        assert rcp in s.tbl and s.n != rcp and s.n != 'PUB'
        msg = s.tid[s.n] + s.tid[rcp] + ecc.i2b(val, 3) + s.pos(s.tid[s.n] + s.tid[rcp]) 
        s.add(msg)
        k.privkey = s.getsk()
        sgn = k.sign(msg)
        if isn: t.sendto(msg + sgn, (HOST, s.tbl[rcp]))            
        t.sendto(msg + sgn, (HOST, s.tbl['PUB']))

    def chat(s, r):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.sendto(b'hi!', (HOST, s.tbl[r]))
        #while (True):
        #    m, a = t.recvfrom(1024)
        #    print (m)
        
    def reset(s):
        with dbm.open(s.n, 'c') as b:
            for x in b.keys(): del b[x]
            k = ecc.ecdsa()
            k.generate()
            s.pk = k.compress(k.pt)
            b[s.n.encode('utf-8')] = s.pk
            b[b'&'] = ecc.i2b(k.privkey, 48)
            
    def savepks(s):
        with dbm.open(s.n, 'c') as b:
            for x in s.tpk: b[x] = s.tpk[x]
    def getsk(s):
        with dbm.open(s.n) as b: return ecc.b2i(b[b'&'])
    def readdb(s):
        with dbm.open(s.n) as b:
            for x in b.keys(): print (len(x), len(b[x]), x, b[x])
            
    def server(s):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for x in range(MAXP):
            try:
                t.bind((HOST, BASP+x))
                break
            except: pass
        s.p = x
        print (s.n, 'using port', s.p + BASP, '(please (i)nitialize)')        
        while (True):
            m, a = t.recvfrom(1024)
            #print ('(%d)<' % len(m)) # debug
            if   m == b'who?': t.sendto(s.pk + s.n.encode('utf-8'), a)
            elif m == b'hi!' :
                print ('hi!')
                #t.sendto(b'ok', a)
            elif len(m) == RLEN: s.manage(m)
            
    def check(s, p, val):
        t = 0
        with dbm.open(s.n) as b:
            for x in [y for y in b.keys() if len(y) == 8 and len(b[y]) == 5]:
                if p == x[:4]: t -= ecc.b2i(b[x][:3])
                if p == x[4:]: t += ecc.b2i(b[x][:3])
        return val - t < DEBT

    def bal(s, p):
        t = 0
        with dbm.open(s.n) as b:
            for x in [y for y in b.keys() if len(y) == 8 and len(b[y]) == 5]:
                if s.tid[p] == x[:4]: t -= ecc.b2i(b[x][:3])
                if s.tid[p] == x[4:]: t += ecc.b2i(b[x][:3])
        return t
    def bals(s): return {x:s.bal(x) for x in s.tid}
    
    def ttime(s):
        with dbm.open(s.n) as b:
            return sum([ ecc.b2i(b[x][3:]) for x in \
                         [y for y in b.keys() if len(y) == 8 and len(b[y]) == 5]])
    def time(s, p):
        t = 0
        with dbm.open(s.n) as b:
            for x in [y for y in b.keys() if len(y) == 8 and len(b[y]) == 5]:
                if s.tid[p] == x[:4]: t += ecc.b2i(b[x][3:])
                if s.tid[p] == x[4:]: t += ecc.b2i(b[x][3:])
        return t
    def times(s): return {x:s.time(x) for x in s.tid}
    
    def pos(s, z):
        with dbm.open(s.n) as b:
            return b[z][3:] if z in b else ecc.i2b(0, 2)    
    def add(s, m):
        print ('%s pays %d to %s' % (s.rvs[m[:4]], ecc.b2i(m[8:11]), s.rvs[m[4:8]]))
        p = ecc.b2i(m[11:])
        x, y = m[:8], m[8:11] + ecc.i2b(p + 1, 2)
        with dbm.open(s.n, 'c') as b:
            if (x in b and p == ecc.b2i(b[x][3:])) or (x not in b and p == 0): b[x] = y

    def manage(s, m): # if not PUB, message can be reduced(104) to Src(5)+Val(3)+Sig(96)
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if s.n != 'PUB': assert m[4:8] == s.tid[s.n]
        k = ecc.ecdsa()
        k.pt = k.uncompress(m[:4] + s.tpk[m[:4]]) # public key sent at init
        assert k.verify(m[13:], m[:13])
        if s.pos(m[:8]) == m[11:13]:
            assert s.check(m[:4], ecc.b2i(m[8:11]))
            s.add(m[:13])        
            if s.n == 'PUB': t.sendto(m, (HOST, s.tbl[s.rvs[m[4:8]]]))
        else: assert ecc.b2i(s.pos(m[:8])) == ecc.b2i(m[11:13]) + 1

    def http(s, arg):
        print('Serving', URLB)
        srv = socketserver.TCPServer((HOST, PORT), handler)
        srv.RequestHandlerClass.nod = arg
        srv.serve_forever()

class handler(http.server.BaseHTTPRequestHandler):    
    nod = None
    def response(s, mime):
        s.send_response(200)
        s.send_header('Content-type', mime)
        s.end_headers()

    def do_POST(s):
        data = s.rfile.read(int(s.headers['Content-Length']))
        print ('DATA:', data.decode('utf-8'))
        jdata = json.loads(data)
        s.response('application/json')
        s.wfile.write(b'{"ok"}')
        
    def do_GET(s):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if 'PUB' in s.nod.tbl: t.sendto(b'hi!', (HOST, s.nod.tbl['PUB'])) # use UDP !
        s.response('text/plain; charset=utf-8')        
        p = 'Times\n%s\nTotal\n%d\nBalances\n%s\nend\n' % (s.nod.times(), s.nod.ttime(), s.nod.bals())
        s.wfile.write(p.encode('utf-8'))
            
def reg(v):
    reg.v = v
    return v

if __name__ == '__main__':
    if len(ecc.sys.argv) == 2: node(ecc.sys.argv[1].upper())
    else: node('PUB')     
# End ⊔net!
