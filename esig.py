#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" 
  **** EHANCED SIGNATURE ****
_______________________________
 Use the 'esig' iOS app to test an a real device
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
COMMUNICATIONS:
 UDP sockets between smartphone simulators and Public
 HTTP for real smartphone with Public
 QRCODE or BLE or NFC between smartphones
FORMAT: 
 message(13):src(4)+dst(4)val(3)nb(2)+sign(96) -> (109)
 (Production system may use 5 bytes ID length, not 4)
 Persistant data use a Key-Value Database (Berkeley)
 (8:5)     src|dst:val|nb for a collected transaction 
 (9:5) '_'|src|dst:val|nb for a pending   transaction
FORMAL DEFINITIONS:
 * Let H a human owning a smartphone
 * Let P a 'Public' server or public mesh of servers
 * Let E called an 'Economy' a: 
  Square Sparse Square Matrix of Natural Couple with Humans-ID dimensions
  Only 'Public' records an Enconomy
 * Let C called a 'Cross' an Economy (Sparce Square Matrix) with: 
  1/ Both diagional vectors with at most one non nul couple
  2/ Column vectors all nuls except one
  3/ Raw vectors all nuls except one
 * Let (B,D) a couple of called ('Balance', 'Date')
 * Let B(H) called Balance of Human H the difference of 
  sum of column balances with the sum of raw balances
 * Let D(H) called Date of Human H the sum of 
  sum of column dates and the sum of raw dates
 * Let T called a Transaction a:
  message Buyer-ID|Selled-ID|Price|Date 
  + Signature by Buyer-ID of the message
OPERATIONS:
 The 3 allowed operations on an economy are:
  1/ Register one Human
   eve send to public: PublicKey(eve) + eve's name
  2/ Pay from one Human to another Human
   alice: '20bob'        => Alice pays (offline) 20 to Bob
   carOl: 'pUb 34 Alice' => Carol pays (online)  34 to Alice 
  3/ Vote from one Human on a segment value (0-100%) 
   TBC
TODO: 
 - Non-regression testing
 - FAQ
 - Switch assert sentences to error managment
_________________________________
CONTACT: laurent.fournier@adox.io
"""

import socket, threading, ecc, re, dbm, http.server, socketserver, json, urllib, requests
MAXP = 10              # Max nb phones
DEBT = 100             # Self-debt limit
RLEN = 109             # Request len (message+signature)
HOST = '192.168.1.13'  # local host
HMIP = '91.168.92.157' # My home IP4 for testing
BASP = 5000            # Base port number
PORT = 50001           # Pub HTTP port
URLH = 'http://%s:%d' % (HMIP, PORT)
URLB = 'http://%s:%d' % (HOST, PORT)         

class node:
    def __init__(s, name):
        s.n, s.tbl, s.rvs, s.tid, s.tpk, s.pk, me = name, {}, {}, {}, {}, b'', ''
        s.reset()
        threading.Thread(target=s.server).start()
        if s.n == 'PUB':
            threading.Thread(target=s.http, args=(s,)).start()
            #print(requests.get(URLH).content.decode('utf-8')) # debug
        while (True):
            c = input('%s>' % s.n)
            if   re.match('^\s*(I|INIT)\s*$',           c, re.I):  print (s.init())
            elif re.match('^\s*(H|M|HELP|DOC|MAN)\s*$', c, re.I):  print (__doc__)
            elif re.match('^\s*(D|DUMP|DATA|BASE)\s*$', c, re.I):  s.readdb()
            elif re.match('^\s*(T|TIME|DATE)\s*$',      c, re.I):  print(s.times())
            elif re.match('^\s*(B|BAL|BALANCE)\s*$',    c, re.I):  print(s.bals())
            elif reg(re.match('^\s*(|P|PUB)\s*(\d+)\s*([A-Z]{3,15})\s*$', c, re.I)): s.commit(reg)
            elif c.upper() in s.tid: s.echo(c.upper())
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
        assert s.bal('PUB') == 0 and s.time('PUB') == 0
        msg = s.tid[s.n] + s.tid[rcp] + ecc.i2b(val, 3) + s.pos(s.tid[s.n] + s.tid[rcp]) 
        s.add(msg)
        k.privkey = s.getsk()
        sgn = k.sign(msg)
        if rcp in s.tbl:
            if isn: t.sendto(msg + sgn, (HOST, s.tbl[rcp]))            
            t.sendto(msg + sgn, (HOST, s.tbl['PUB']))
        else:
            pass # iphone case

    def echo(s, r):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.sendto(b'hi!', (HOST, s.tbl[r]))
        
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
            if   m == b'who?': t.sendto(s.pk + s.n.encode('utf-8'), a)
            elif m == b'hi!' : print ('hi!')
            elif len(m) == RLEN:          s.manage(m)
            elif len(m)>48 and len(m)<60: s.register(m)

    def register(s, m):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        name = m[48:].decode('utf-8')
        s.tid[name], s.tpk[m[:4]], s.rvs[m[:4]] = m[:4], m[4:48], name
        if s.n == 'PUB':
            for x in [y for y in s.tbl if y != 'PUB']: s.sendpk(s.tid[x], m)
                
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
    def bals(s): return {x:s.bal(x) for x in [y for y in s.tid if y != 'PUB']}
    
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
    def times(s): return {x:s.time(x) for x in [y for y in s.tid if y != 'PUB']}
    
    def pos(s, z):
        with dbm.open(s.n) as b:
            return b[z][3:] if z in b else ecc.z2
        
    def add(s, m):
        print ('%s pays %d to %s' % (s.rvs[m[:4]], ecc.b2i(m[8:11]), s.rvs[m[4:8]]))        
        p = ecc.b2i(m[11:])
        x, y = m[:8], m[8:11] + ecc.i2b(p + 1, 2)
        with dbm.open(s.n, 'c') as b:
            if (x in b and p == ecc.b2i(b[x][3:])) or (x not in b and p == 0): b[x] = y

    def manage(s, m): # if not PUB, message can be reduced to Src+Val+Sig
        t, k = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), ecc.ecdsa()
        if s.n != 'PUB': assert m[4:8] == s.tid[s.n]
        k.pt = k.uncompress(m[:4] + s.tpk[m[:4]]) # public key sent at init
        assert k.verify(m[13:], m[:13])
        if s.pos(m[:8]) == m[11:13]:
            assert s.check(m[:4], ecc.b2i(m[8:11]))
            s.add(m[:13])
            dst = s.rvs[m[4:8]]
            if s.n == 'PUB':
                if dst in s.tbl: t.sendto(m, (HOST, s.tbl[dst]))
                else: pass # add pending
        else: assert ecc.b2i(s.pos(m[:8])) == ecc.b2i(m[11:13]) + 1

    def sendpk(s, dst, m):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.sendto(m, (HOST, s.tbl[s.rvs[dst]]))

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

    def do_POST(s): # online transaction because only PUB has an HTTP server
        d, k, rt = s.rfile.read(int(s.headers['Content-Length'])), ecc.ecdsa(), {}
        if len(d) > 48 and len(d) < 63: # register -> pk + name
            s.nod.me = d[48:].decode('utf-8')
            print ('Register', s.nod.me)
            s.nod.tid[s.nod.me] = d[:4]
            s.nod.rvs[d[:4]] = s.nod.me
            s.nod.tpk[d[:4]] = d[4:48]
            s.nod.sendpk(s.nod.tid['PUB'], d)
            #print (s.nod.tid)            
            s.response('application/json')            
            for x in [y for y in s.nod.tbl if y != 'PUB']:
                nid = s.nod.tid[x]
                rt[x] = ecc.base64.b64encode(nid + s.nod.tpk[nid]).decode('utf-8')
            s.wfile.write(json.dumps(rt).encode('utf-8'))
        elif len(d) == RLEN and s.nod.me in s.nod.tid: # pay transaction(13)+signature(96)
            print ('Pay', len(s.nod.tid[s.nod.me]), len(s.nod.tpk[s.nod.tid[s.nod.me]]))
            k.pt = k.uncompress(s.nod.tid[s.nod.me] + s.nod.tpk[s.nod.tid[s.nod.me]])
            assert k.verify(d[13:], d[:13])
            s.nod.manage(d)
            s.response('application/octet-stream')
            s.wfile.write(b'ok')
        else: # bad request
            s.response('application/octet-stream')
            s.wfile.write(b'ko')
        
    def do_GET(s): # does not show the all matrix for Privacy
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
