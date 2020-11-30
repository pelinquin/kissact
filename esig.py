#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" 
  **** EHANCED SIGNATURE ****
_________________________________________________________________
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
 message(16):src(5)+dst(5)+val(3)+type(1)+date(2)+sign(96)=(112)
 Persistant data use a Key-Value Database (Berkeley)
 (16:96) src|dst|val|typ|date : sign => reconding transaction 
 (10:18)     src|dst : val|tax|date  => collected transaction
 (11:18) '_'|src|dst : val|tax|date  => pending   transaction
 (2:6)       group : cumul
 (3:4)   '_'|group : points 
FORMAL DEFINITIONS:
 * Let H a human owning a smartphone
 * Let P a 'Public' server or public mesh of servers
 * Let E called an 'Economy' a: 
  Sparse Square Matrix of Natural Couple with Humans-ID indix
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
SIGNATURE:
 ecc :ECDSA P384 + SHA384-> len(pk)=len(sk)=48 len(sig)=96
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
__________________________________________________________________
CONTACT: laurent.fournier@adox.io (https://adox.io)
"""

import socket, threading, ecc, re, dbm, http.server, socketserver, json, urllib, requests
MAXP = 10              # Max nb phones
DEBT = 1000            # Self-debt limit
RLEN = 112             # Request len (message+signature)
DBKL = 10              # Key   record length
DBVL = 8               # Value record length 
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
            #print(requests.get(URLH).content.decode('utf-8')) # debug at home !
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
                s.tbl[name], s.tid[name], s.tpk[m[:5]], s.rvs[m[:5]] = a[1], m[:5], m[5:48], name
            except: break
        t.settimeout(None)
        s.savepks()
        return s.tbl
    
    def commit(s, r):
        t, k = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), ecc.ecdsa()
        isn, val, rcp = (r.v.group(1) != 'PUB'), int(r.v.group(2)), r.v.group(3).upper()
        assert s.check(s.tid[s.n], val)
        assert rcp in s.tbl and s.n != rcp and s.n != 'PUB'
        assert s.bal(s.tid['PUB']) == 0 and s.time(s.tid['PUB']) == 0
        msg = s.tid[s.n] + s.tid[rcp] + ecc.i2b(val, 3) + ecc.z1 + s.pos(s.tid[s.n] + s.tid[rcp]) 
        k.privkey = s.getsk()
        sgn = k.sign(msg)
        s.add(msg + sgn)        
        if rcp in s.tbl:
            if isn: t.sendto(msg + sgn, (HOST, s.tbl[rcp]))
            t.sendto(msg + sgn, (HOST, s.tbl['PUB']))
        else:
            print ('iphone') # iphone case

    def echo(s, r):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.sendto(b'hi!', (HOST, s.tbl[r]))
        
    def reset(s):
        with dbm.open(s.n, 'c') as b:
            for x in b.keys(): del b[x]
            k = ecc.ecdsa()
            k.generate()
            s.pk = k.compress(k.pt)
            b[s.n.encode('utf-8')] = s.pk    # My Public  key
            b[b'&'] = ecc.i2b(k.privkey, 48) # My Private key
            if s.n == 'PUB': b[ecc.z2], b[b'_'+ecc.z2] = ecc.z6, ecc.z4
            
    def savepks(s):
        with dbm.open(s.n, 'c') as b:
            for x in s.tpk: b[x] = s.tpk[x] # Others Public keys

    def getsk(s):
        with dbm.open(s.n) as b: return ecc.b2i(b[b'&']) # Authentication

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
            elif len(m) == RLEN:          print (s.manage(m))
            elif len(m)>48 and len(m)<60: s.register(m)
            else: print ('ko', len(m))

    def register(s, m):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        name = m[48:].decode('utf-8')
        s.tid[name], s.tpk[m[:5]], s.rvs[m[:5]] = m[:5], m[5:48], name
        for x in [y for y in s.tbl if y != 'PUB' and s.n == 'PUB']: s.sendpk(s.tid[x], m)
                
    def bal(s, p):
        if s.rvs[p] == 'PUB': return 0
        t = 0
        with dbm.open(s.n) as b:
            for x in [y for y in b.keys() if len(y) == DBKL and len(b[y]) == DBVL]:
                if   p == x[:5]: t -= ecc.b2i(b[x][:3])
                elif p == x[5:]: t += ecc.b2i(b[x][:3])
                else: assert s.n == 'PUB'
        return t
    def bals(s):
        if s.n == 'PUB':
            return {s.rvs[x]:s.bal(x) for x in [s.tid[y] for y in s.tid if y != 'PUB']}
        else:
            return s.bal(s.tid[s.n])
    def check(s, p, val): return (val > 0) and (val - s.bal(p) < DEBT)
    
    def ttime(s):
        with dbm.open(s.n) as b:
            return sum([ ecc.b2i(b[x][6:]) for x in \
                         [y for y in b.keys() if len(y) == DBKL and len(b[y]) == DBVL]])
    def time(s, p):
        if s.rvs[p] == 'PUB': return 0
        t = 0
        with dbm.open(s.n) as b:
            for x in [y for y in b.keys() if len(y) == DBKL and len(b[y]) == DBVL]:
                if   p == x[:5]: t += ecc.b2i(b[x][6:])
                elif p == x[5:]: t += ecc.b2i(b[x][6:])
                else: assert s.n == 'PUB'
        return t
    def times(s):
        if s.n == 'PUB':
            return {s.rvs[x]:s.time(x) for x in [s.tid[y] for y in s.tid if y != 'PUB']}
        else:
            return s.time(s.tid[s.n])
        
    def pos(s, z):
        with dbm.open(s.n) as b:
            return b[z][6:] if z in b else ecc.z2
        
    def add(s, m): 
        print ('%s pays %d to %s' % (s.rvs[m[:5]], ecc.b2i(m[10:13]), s.rvs[m[5:10]]))        
        p, v, x, y = ecc.b2i(m[14:16]), ecc.b2i(m[10:13]), m[:10], ecc.b2i(m[13:14])
        t, q, g = v//10 if y == 0 else 0, ecc.z2, b'_' + ecc.z2 # Default tax value: 10%
        with dbm.open(s.n, 'c') as b:
            if x not in b and p == 0:
                print ("ici")
                b[x] = ecc.i2b(v,    3) + ecc.i2b(t,    3) + ecc.i2b(1  , 2) 
            elif (x in b and p == ecc.b2i(b[x][6:])):
                print ("la")
                ov, ot, op = ecc.b2i(b[x][:3]), ecc.b2i(b[x][3:6]), ecc.b2i(b[x][6:])
                b[x] = ecc.i2b(v+ov, 3) + ecc.i2b(t+ot, 3) + ecc.i2b(1+op, 2)
            else: assert True
            if s.n != 'PUB': b[m[:16]] = m[16:]
            else: b[q], b[g] = ecc.i2b(len(s.tpk), 6), ecc.i2b(ecc.b2i(b[g]) + t, 6)

    def manage(s, m):
        t, k = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), ecc.ecdsa()
        k.pt = k.uncompress(m[:5] + s.tpk[m[:5]])         
        if s.n != 'PUB' and m[5:10] != s.tid[s.n]:    return False
        if not k.verify(m[16:], m[:16]):              return False
        if s.pos(m[:10]) == m[14:16]:
            if not s.check(m[:5], ecc.b2i(m[10:13])): return False
            s.add(m)
            dst = s.rvs[m[5:10]]
            if s.n == 'PUB' and dst in s.tbl: t.sendto(m, (HOST, s.tbl[dst]))
            return True
        else:
            return ecc.b2i(s.pos(m[:10])) == ecc.b2i(m[14:16]) + 1

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
        d, rt = s.rfile.read(int(s.headers['Content-Length'])), {}
        if len(d) > 48 and len(d) < 60: # register -> pk + name
            s.nod.me = d[48:].decode('utf-8')
            print ('Phone register', s.nod.me)
            s.nod.tid[s.nod.me] = d[:5]
            s.nod.rvs[d[:5]] = s.nod.me
            s.nod.tpk[d[:5]] = d[5:48]
            s.nod.sendpk(s.nod.tid['PUB'], d)
            s.response('application/json')            
            for x in [y for y in s.nod.tbl if y != 'PUB']:
                nid = s.nod.tid[x]
                rt[x] = ecc.base64.b64encode(nid + s.nod.tpk[nid]).decode('utf-8')
            s.wfile.write(json.dumps(rt).encode('utf-8'))
        elif s.manage_post(d): s.wfile.write(b'ok')
        else:                  s.wfile.write(b'ko') 

    def manage_post(s, d):
        k = ecc.ecdsa()
        s.response('application/octet-stream')
        if len(d) != RLEN:                                          return False
        if s.nod.me not in s.nod.tid:                               return False 
        if not s.nod.check(s.nod.tid[s.nod.me], ecc.b2i(d[10:13])): return False
        k.pt = k.uncompress(s.nod.tid[s.nod.me] + s.nod.tpk[s.nod.tid[s.nod.me]])
        if not k.verify(d[16:], d[:16]):                            return False
        return s.nod.manage(d)
        
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
