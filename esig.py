#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" 
  **** EHANCED SIGNATURE ****

 (Basic version to keep the code simple !)
USAGE: 
 './esig.py'       -> run Public (PUB)
 './esig.py Alice' -> run Alice's phone  
 './esig.py BoB'   -> run Bob's   phone
COMMANDS:
 i => init network (UDP ports)
 b => get local balances
 d => local dadabase dump
OPERATION:
 alice: '20bob'    => Alice  pays 20 to Bob
 carOl: '34 Alice' => Carole pays 34 to Alice 
FORMAT: 
 message(15):src(5)+dst(5)val(3)nb(2)+sign(96) -> (111)
CONTACT: laurent.fournier@adox.io
"""
import socket, threading, ecc, re, dbm
BASP = 5000        # Base port number
MAXP = 10          # Max nb phones
HOST = '127.0.0.1' # LOCAL IP
DEBP = 100         # Self-debt limit
RLEN = 111         # Request len (message+signature)

class node:
    def __init__(s, name):
        s.n, s.tbl, s.tid, s.tpk, s.pk = name, {}, {}, {}, b''
        s.reset()
        threading.Thread(target=s.server).start()
        while (True):
            c = input('%s>' % s.n)
            if   re.match('^\s*(I|INIT)\s*$',             c, re.I):  print (s.init())
            elif re.match('^\s*(H|HELP|DOC)\s*$',         c, re.I):  print (__doc__)
            elif re.match('^\s*(D|DUMP|DATA|BASE)\s*$',   c, re.I):  s.readdb()
            elif re.match('^\s*(B|BAL|BALANCE)\s*$',      c, re.I):  print(s.time(), s.bals())
            elif reg(re.match('^\s*(\d+)\s*([A-Z]+)\s*$', c, re.I)): s.commit(reg)
            else: print('Command not found')

    def init(s):
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for x in range(MAXP): t.sendto(b'who?', (HOST, BASP+x))
        t.settimeout(1)
        while (True):
            try:
                m, a = t.recvfrom(1024)
                name = m[48:].decode('utf-8')
                s.tbl[name], s.tid[name], s.tpk[m[:5]] = a[1], m[:5], m[5:48]
            except: break
        t.settimeout(None)
        return s.tbl
    
    def commit(s, r):
        t, k = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), ecc.ecdsa()
        val, rcp = int(r.v.group(1)), r.v.group(2).upper()
        if s.check(s.tid[s.n], val) == False: return
        assert rcp in s.tbl and s.n != rcp and s.n != 'PUB'
        msg = s.tid[s.n] + s.tid[rcp] + ecc.i2b(val, 3) + s.pos(s.tid[s.n] + s.tid[rcp]) 
        s.add(msg)
        k.privkey = s.getsk()
        sgn = k.sign(msg)
        t.sendto(msg + sgn, (HOST, s.tbl['PUB']))
        t.sendto(msg + sgn, (HOST, s.tbl[rcp]))
        
    def reset(s):
        with dbm.open(s.n, 'c') as b:
            for x in b.keys(): del b[x]
            k = ecc.ecdsa()
            k.generate()
            s.pk = k.compress(k.pt)
            b[s.n.encode('utf-8')] = s.pk
            b[b'&'] = ecc.i2b(k.privkey, 48)
            
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
            if m == b'who?': t.sendto(s.pk + s.n.encode('utf-8'), a)
            elif len(m) == RLEN: s.manage(m)
            
    def check(s, p, val):
        t = 0
        with dbm.open(s.n) as b:
            for x in [y for y in b.keys() if len(y) == 10 and len(b[y]) == 5]:
                if p == x[:5]: t -= ecc.b2i(b[x][:3])
                if p == x[5:]: t += ecc.b2i(b[x][:3])
        return val - t < DEBP
    def bal(s, p):
        t = 0
        with dbm.open(s.n) as b:
            for x in [y for y in b.keys() if len(y) == 10 and len(b[y]) == 5]:
                if s.tid[p] == x[:5]: t -= ecc.b2i(b[x][:3])
                if s.tid[p] == x[5:]: t += ecc.b2i(b[x][:3])
        return t
    def bals(s):
        return {x:s.bal(x) for x in [y for y in s.tid if y != 'PUB']}
    def time(s):
        with dbm.open(s.n) as b:
            return sum([ ecc.b2i(b[x][3:]) for x in \
                         [y for y in b.keys() if len(y) == 10 and len(b[y]) == 5]])
    def pos(s, z):
        with dbm.open(s.n) as b:
            return b[z][3:] if z in b else ecc.i2b(0, 2)    
    def add(s, m):
        p = ecc.b2i(m[13:])
        x, y = m[:10], m[10:13] + ecc.i2b(p + 1, 2)
        with dbm.open(s.n, 'c') as b:
            if (x in b and p == ecc.b2i(b[x][4:])) or (x not in b and p == 0): b[x] = y

    def manage(s, m): # if not PUB, message can be reduced(104) to Src(5)+Val(3)+Sig(96)
        if s.n != 'PUB': assert m[5:10] == s.tid[s.n]
        assert s.pos(m[:10]) == m[13:15]
        k = ecc.ecdsa()
        k.pt = k.uncompress(m[:5] + s.tpk[m[:5]]) # public key sent at init
        assert k.verify(m[15:], m[:15]) and s.check(m[:5], ecc.b2i(m[10:13]))
        s.add(m[:15])
    
def reg(v):
    reg.v = v
    return v

if __name__ == '__main__':
    if len(ecc.sys.argv) == 2: node(ecc.sys.argv[1].upper())
    else: node('PUB')     
# End ⊔net!
