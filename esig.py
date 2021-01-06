#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" 
  **** ENHANCED SIGNATURE ****
_________________________________________________________________
 Use the 'esig' iOS app to test on a real device
USAGE: 
 './esig.py'       -> run Public (PUB)
 './esig.py Alice' -> run Alice's phone  
 './esig.py BoB'   -> run Bob's   phone
COMMANDS:
 i => init network (UDP ports)
 b => get balance(s)
 t => get discret time cross values 
 d => local dadabase dump (raw)
 s => synchronize with groups values
 h => help
COMMUNICATIONS:
 UDP sockets between smartphone simulators and Public
 HTTP for real smartphone with Public
 QRCODE or BLE or NFC between smartphones
FORMAT: 
 Persistant data use a Key-Value Database (Berkeley)
  Transaction112(16:96) = src5|dst5|val3|type1|date2 : sign96
    => collected if not Public, => pending if Public
  Matrix:
   Element15(10:5) src5|dst5 : cumul_val3|last_date2
  Vectors:
   Element11(5:6)        src5 : cumul_tax6
  Groups:
   Cumul8(2:6)           group2 : cumul6
   Definition11(3:4) '_'|group2 : tot_pt4
   Membership8(7:1) src5|group2 : pt1
  Types:
   NumType(1:3*n) Num1:(Group2|ratio1)*n 
FORMAL DEFINITIONS:
 * Let H a human owning a smartphone
 * Let P a 'Public' server or public mesh of servers
 * Let E called an 'Economy' a: 
  - Sparse Square Matrix of Natural Couple with Humans-ID indix
  - Tax group vector
  - Tax humans vector
  Only 'Public' records the Enconomy data
 * Let C called a 'Cross' an Economy (Sparce Square Matrix) with: 
  1/ Both diagional vectors with at most one none-nul couple
  2/ Column vectors all nuls except one
  3/ Raw    vectors all nuls except one
 * Let (B,D) a couple of called ('Balance', 'Date')
 * Let B(H) called Balance of Human H the difference of 
  sum of column balances with the sum of raw balances
 * Let D(H) called Date of Human H the sum of 
  sum of column dates and the sum of raw dates
 * Let T called a Transaction a:
  message Buyer-ID|Selled-ID|Price|Date 
  + Signature by Buyer-ID of the message
 * Let G called a Group with a positive tax vector value
  G0 is the group of all members
  A property distribution is defined for each group with positive values
  (a nul value for someone means he is not member)
  A group distribution is defined for each good for sale/service
  A user of a service must be member of at least one os its group
  Service Income is alocated according to good/groups distribution
SIGNATURE:
 ecc :ECDSA P384 + SHA384-> len(pk)=len(sk)=48 len(sig)=96
OPERATIONS:
 The 3 allowed operations on an economy are:
  1/ Register one Human
   eve send to public: PublicKey(eve) + eve's name
     Apply for a group:
   alice: 'g1 3' => Alice register to group 1 with weigth of 3 points
  2/ Pay from one Human to another Human
   alice: '20bob'        => Alice pays (offline) 20 to Bob
   carOl: 'pUb 34 Alice' => Carol pays (online)  34 to Alice 
  3/ Vote from one Human on a segment value (0-100%) 
   TBC
TODO: 
 - Non-regression testing
 - FAQ
 - Convert assert sentences to error managment
__________________________________________________________________
CONTACT: laurent.fournier@adox.io (https://adox.io)
"""

import socket, threading, ecc, re, dbm, http.server, socketserver, json, urllib, requests, fractions
MAXP = 10              # Max nb phones
DEBT = 1000            # Self-debt limit
MLEN = 16              # Message len
RLEN = 112             # Request len (message+signature) 
MEKL = 10              # Matrix Element Key Length
MEVL = 5               # Matrix Element Val Length
VEKL = 5               # Vector Element Key Length
VEVL = 6               # Vector Element Val Length
HOST = '192.168.1.13'  # local host (Orsay)
#HOST = '10.42.0.1'     # local host (Longues)
HMIP = '91.168.92.157' # My home IP4 for testing
BASP = 5000            # Base port number
PORT = 50001           # Pub HTTP port
URLH = 'http://%s:%d' % (HMIP, PORT)
URLB = 'http://%s:%d' % (HOST, PORT)

# Full-Comunism    -> no private property TAX0=100,TAX1=0
# Full-Capitalism  -> no taxes            TAX0=0,TAX1=0
# Simple Economy   -> G0 group            TAX0>0,TAX0<100,TAX1=0
# Enhanced Economy -> G0 and G1 groups    TAX0>0,TAX1>0,TAX0+TAX1<100 
TAX0 = 20
TAX1 = 10

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
            elif re.match('^\s*(G|GR|GROUP)\s*$',       c, re.I):  print(s.groups())
            elif re.match('^\s*(S|SYNC)\s*$',           c, re.I):  s.callsync()
            elif reg(re.match('^\s*(|P|PUB)\s*(\d{1,4})\s*([A-Z]{3,15})\s*$', c, re.I)): s.commit(reg)
            elif reg(re.match('^\s*(G|GR|GROUP)\s*(\d{1,3})\s+(\d{1,3})\s*$', c, re.I)): s.group(reg)
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
    
    def groups(s):
        with dbm.open(s.n) as b:
            g, d = {}, {}
            for x in [y for y in b.keys() if len(y) == 7 and len(b[y]) == 1]:
                gr, el, pt = ecc.b2i(x[5:]), s.rvs[x[:5]], ecc.b2i(b[x])
                h = g[gr] if gr in g else {}
                h[el] = pt
                g[gr] = h
            for x in [y for y in b.keys() if len(y) == 3 and len(b[y]) == 4]:
                d[ecc.b2i(x[1:])] = ecc.b2i(b[x])
            return (g, d)
        
    def group(s, r):
        t, g, p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), int(r.v.group(2)), int(r.v.group(3))%0xFF
        msg = s.tid[s.n] + ecc.i2b(g, 2) + ecc.i2b(p, 1)
        s.regrp(msg)
        t.sendto(msg, (HOST, s.tbl['PUB']))
    
    def commit(s, r):
        t, k = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), ecc.ecdsa()
        isn, val, rcp = (r.v.group(1) != 'PUB'), int(r.v.group(2)), r.v.group(3).upper()
        assert s.check(s.tid[s.n], val)
        assert rcp in s.tid and s.n != rcp and s.n != 'PUB'
        assert s.bal(s.tid['PUB']) == 0 and s.time(s.tid['PUB']) == 0
        msg = s.tid[s.n] + s.tid[rcp] + ecc.i2b(val, 3) + ecc.z1 + s.pos(s.tid[s.n] + s.tid[rcp]) 
        k.privkey = s.getsk()
        sgn = k.sign(msg)
        s.add(msg + sgn) # add src                  
        if rcp in s.tbl:
            if isn: t.sendto(msg + sgn, (HOST, s.tbl[rcp]))
            t.sendto(msg + sgn, (HOST, s.tbl['PUB']))
            s.sync(t.recvfrom(1024)[0])
        else:
            print ('iphone') # iphone case
            t.sendto(msg + sgn, (HOST, s.tbl['PUB']))

    def callsync(s):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.sendto(b'sync', (HOST, s.tbl['PUB']))
        s.sync(t.recvfrom(1024)[0])
        print(s.bals())
        
    def echo(s, r):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.sendto(b'hi!', (HOST, s.tbl[r]))
        
    def reset(s):
        with dbm.open(s.n, 'c') as b:
            for x in b.keys(): del b[x]
            k = ecc.ecdsa()
            k.generate()
            s.pk = k.compress(k.pt)          # My Public  key
            b[b'&'] = ecc.i2b(k.privkey, 48) # My Private key
            #if s.n == 'PUB':
            b[ecc.z2], b[b'_'+ecc.z2] = ecc.z6, ecc.z4
            b[s.pk[:5]] = ecc.z6
            # Types
            b[ecc.i2b(0)] = ecc.i2b(15, 3)                        # Type0=G0:15%
            b[ecc.i2b(1)] = ecc.i2b(13, 3) + ecc.i2b(0x100+80, 3) # Type1=G0:13%G1:80%
            
    def savepks(s):
        with dbm.open(s.n, 'c') as b:
            for x in s.tpk: b[b'#'+x] = s.tpk[x] # Others Public keys
            if len(s.tpk) > 0: b[b'_'+ecc.z2] = ecc.i2b(len(s.tpk)-1, 4)

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
            if   m == b'who?':                t.sendto(s.pk + s.n.encode('utf-8'), a)
            elif m == b'hi!' :                print ('hi!')
            elif m == b'sync':                s.managesync(a)
            elif len(m) >= RLEN:              s.manage(m, a)
            elif len(m) == 8:                 s.regrp(m)
            elif len(m) > 48 and len(m) < 60: s.register(m)
            else: print ('ko', len(m))

    def regrp(s, m):
        x, h, g, pr, p, y, z = m[:5], m[5:7], b'_' + m[5:7], m[7:8], ecc.b2i(m[7:8]), 0, 0
        with dbm.open(s.n, 'c') as b:
            b[x+h] = pr
            if h not in b: b[h] = ecc.z6
            z = ecc.b2i(b[g]) if g in b else 0
            b[g] = ecc.i2b(z + p, 4)
            
    def register(s, m):
        name = m[48:].decode('utf-8')
        s.tid[name], s.tpk[m[:5]], s.rvs[m[:5]] = m[:5], m[5:48], name
        for x in [y for y in s.tbl if y != 'PUB' and s.n == 'PUB']: s.sendpk(s.tid[x], m)
                
    def bal(s, p): # cross(p) - tax(p) + sum_groups (contrib*rate(p))
        if s.rvs[p] == 'PUB' or len(s.tid) < 2: return 0
        t, l, q0, q1 = fractions.Fraction(0), len(s.tid)-1, ecc.z2, ecc.i2b(1, 2)
        with dbm.open(s.n) as b:
            #assert len(s.tid) == ecc.b2i(b[b'_'+q0]) + 1 
            for x in [y for y in b.keys() if len(y) == MEKL and len(b[y]) == MEVL]:
                if   p == x[:5]: t -= ecc.b2i(b[x][:3])
                elif p == x[5:]: t += ecc.b2i(b[x][:3])
                else: assert s.n == 'PUB'                
            t -= ecc.b2i(b[p]) if p in b else 0
            t += fractions.Fraction(ecc.b2i(b[q0]), l) 
            if q1 in b and b'_' + q1 in b:
                r = ecc.b2i(b[p+q1]) if p + q1 in b else 0
                t += fractions.Fraction(ecc.b2i(b[q1]) * r, ecc.b2i(b[b'_'+q1])) 
            return t
    
    def bals(s):
        if s.tid == {}: return 0
        if s.n == 'PUB':
            l = {s.rvs[x]:s.bal(x) for x in [s.tid[y] for y in s.tid if y != 'PUB']}
            assert sum(l.values()) == 0
            return l
        else:
            return s.bal(s.tid[s.n])
    def check(s, p, val): return (val > 0) and (val - s.bal(p) < DEBT)
    
    def ttime(s):
        with dbm.open(s.n) as b:
            return sum([ ecc.b2i(b[x][3:]) for x in \
                         [y for y in b.keys() if len(y) == MEKL and len(b[y]) == MEVL]])
    def time(s, p):
        if s.rvs[p] == 'PUB': return 0
        t = 0
        with dbm.open(s.n) as b:
            for x in [y for y in b.keys() if len(y) == MEKL and len(b[y]) == MEVL]:
                if   p == x[:5]: t += ecc.b2i(b[x][3:])
                elif p == x[5:]: t += ecc.b2i(b[x][3:])
                else: assert s.n == 'PUB'
        return t
    def times(s):
        if s.n == 'PUB':
            return (s.ttime(), {s.rvs[x]:s.time(x) for x in [s.tid[y] for y in s.tid if y != 'PUB']})
        else:
            return s.time(s.tid[s.n])
        
    def pos(s, z):
        with dbm.open(s.n) as b:
            return b[z][3:] if z in b else ecc.z2

    def add(s, m): # 1 cross 2 tax 3 groups
        x, r, d, p, v = m[:10], m[:5], m[5:10], ecc.b2i(m[14:16]), ecc.b2i(m[10:13])
        g0, g1 = ecc.z2, ecc.i2b(1, 2)
        print ('%s pays %d to %s' % (s.rvs[r], v, s.rvs[d])) 
        with dbm.open(s.n, 'c') as b:
            t, u, w, y = v*TAX0//100, 0, 0, ecc.b2i(b[r]) if r in b else 0
            if (x in b and p == ecc.b2i(b[x][3:])): w = ecc.b2i(b[x][:3])
            else: assert x not in b and p == 0
            q0, q1 = ecc.b2i(b[g0]), ecc.b2i(b[g1]) if g1 in b else 0
            b[x]  = ecc.i2b(w + v - (t+u), 3) + ecc.i2b(1 + p, 2)
            b[g0] = ecc.i2b(q0 + t, 6)
            if r+g1 in b:
                u = v*TAX1//100
                b[g1] = ecc.i2b(q1 + u, 6)
            b[r]  = ecc.i2b(y + t + u, 6) # t+u
            
    def sync(s, m):
        with dbm.open(s.n, 'c') as b:
            g0, g1, k = ecc.z2, ecc.i2b(1, 2), ecc.ecdsa()
            k.pt = k.uncompress(s.tid['PUB'] + s.tpk[s.tid['PUB']])       
            if k.verify(m[-96:], m[:-96]):
                if ecc.b2i(b[g0]) < ecc.b2i(m[:6]): b[g0] = m[:6]
                if len(m) == 116 and g1 in b:
                    if ecc.b2i(b[g1]) < ecc.b2i(m[10:16]):    b[g1]      = m[10:16]
                    if ecc.b2i(b[b'_'+g1]) < ecc.b2i(m[16:]): b[b'_'+g1] = m[16:20]
                
    def readsync(s): 
        with dbm.open(s.n) as b:
            g0, g1, k = ecc.z2, ecc.i2b(1, 2), ecc.ecdsa()
            msg = b[g0] + ecc.z4
            if g1 in b: msg += b[g1] + b[b'_'+g1]
            k.privkey = s.getsk()
            sgn = k.sign(msg)
            return msg + sgn

    def pending(s, m): 
        with dbm.open(s.n, 'c') as b: b[m[:MLEN]] = m[MLEN:] 
        
    def managesync(s, a):
        print ("Sync request")
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if s.n == 'PUB': t.sendto(s.readsync(), a)
        
    def manage(s, m, a=None):
        t, k = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), ecc.ecdsa()
        k.pt, dst = k.uncompress(m[:5] + s.tpk[m[:5]]), s.rvs[m[5:10]]         
        if s.n != 'PUB' and m[5:10] != s.tid[s.n]                    : return False
        if not k.verify(m[MLEN:RLEN], m[:MLEN])                          : return False
        if len(m) > RLEN: s.sync(m[RLEN:])
        if s.pos(m[:10]) == m[14:16]:
            if s.n == 'PUB' and not s.check(m[:5], ecc.b2i(m[10:13])): return False
            s.add(m) # add dst or PUB
            if s.n == 'PUB' and a:
                t.sendto(s.readsync(), a)
                if dst in s.tbl:
                    t.sendto(m + s.readsync(), (HOST, s.tbl[dst]))
                else:
                    print ('record for iphone')
                    s.pending(m[:RLEN]) 
                print (s.bals())
            return True
        else:
            return ecc.b2i(s.pos(m[:10])) == ecc.b2i(m[14:16]) + 1

    def sendpk(s, dst, m):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.sendto(m, (HOST, s.tbl[s.rvs[dst]]))

    def dump_pending(s):
        with dbm.open(s.n) as b:
            l = b''
            for x in [y for y in b.keys() if len(y) == MLEN and len(b[y]) == RLEN]:
                if s.tid[s.me] == x[5:10]:
                    print ("dump pending") 
                    l += x+b[x]
                    del b[x]
        return (l)

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

    def do_POST(s): # online transaction because only PUB has a HTTP server
        d, rt = s.rfile.read(int(s.headers['Content-Length'])), {}
        if len(d) > 48 and len(d) < 60: # register -> pk + name
            s.nod.me = d[48:].decode('utf-8')
            print ('Phone register', s.nod.me)
            s.nod.tid[s.nod.me] = d[:5]
            #print (s.nod.tid)
            s.nod.rvs[d[:5]] = s.nod.me
            s.nod.tpk[d[:5]] = d[5:48]
            s.nod.savepks()
            print ('PUB', s.nod.tid['PUB'])
            s.nod.sendpk(s.nod.tid['PUB'], d)
            s.response('application/json')            
            for x in [y for y in s.nod.tbl if y != 'PUB']:
                nid = s.nod.tid[x]
                rt[x] = ecc.base64.b64encode(nid + s.nod.tpk[nid]).decode('utf-8')
            s.wfile.write(json.dumps(rt).encode('utf-8'))
        elif s.manage_post(d):
            s.wfile.write(s.nod.dump_pending()) 
        else:
            s.wfile.write(b'ko') 
            
    def manage_post(s, d):
        k = ecc.ecdsa()
        s.response('application/octet-stream')
        if len(d) != RLEN:                                          return False
        if s.nod.me not in s.nod.tid:                               return False 
        if not s.nod.check(s.nod.tid[s.nod.me], ecc.b2i(d[10:13])): return False
        k.pt = k.uncompress(s.nod.tid[s.nod.me] + s.nod.tpk[s.nod.tid[s.nod.me]])
        if not k.verify(d[16:], d[:16]):                            return False
        return s.nod.manage(d)
        
    def do_GET(s): # does not show the all the matrix for Privacy
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if 'PUB' in s.nod.tbl: t.sendto(b'hi!', (HOST, s.nod.tbl['PUB'])) # use UDP !
        s.response('text/plain; charset=utf-8')        
        p = 'Times\n%s\nTotal\n%d\nBalances\n%s\n' % (s.nod.times(), s.nod.ttime(), s.nod.bals())
        g = 'Groups\n%s %s\n' % s.nod.groups()
        s.wfile.write(p.encode('utf-8') + g.encode('utf-8'))
            
def reg(v):
    reg.v = v
    return v

if __name__ == '__main__':
    if len(ecc.sys.argv) == 2: node(ecc.sys.argv[1].upper())
    else: node('PUB')     
# End ⊔net!
