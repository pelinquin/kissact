#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" 
No strategy if Bloomfilter returns a false positive
<src:8><num:2><dst:8><mnt:4><bal:4><dat:4><ack:96><bl:BL_SIZE><hash:16>
"""

import ecc
from simplebloom import BloomFilter

BL_SIZE = 92 # 70 on unix
Z10 = ecc.i2b(0, 10)
SIZE = 48 + 46 + BL_SIZE + 96
SAJ = 8 + 4 + 4 + 144 + 96 # id+mnt+dat+ack+sign
BASE = 1000

def mnt(x):  return ecc.i2b(x, 4)
def getm(x): return ecc.b2i(x[18:22])
def bal(x):  return ecc.i2b(x, 4)
def getb(x): return ecc.b2i(x[22:26])
def num(x):  return ecc.i2b(x, 2)
def getn(x): return ecc.b2i(x[8:10])
def hsh(x=b''): return ecc.hashlib.sha256(x).digest()[:16]
def geth(x): return x[-16:]
def bl():    return ecc.i2b(0, BL_SIZE)
def now():   return int(ecc.time.mktime(ecc.time.gmtime()))
def dat(d):  return ecc.i2b(d, 4)
def getd(x): return ecc.b2i(x[26:30])
def ddod(t): return ecc.time.strftime('%d/%m/%y %H:%M:%S', ecc.time.localtime(float(t)))

class agent:
    
    def __init__(s, root=None):
        s.k, s.o = ecc.ecdsa(), ecc.ecdsa()
        s.k.generate()
        s.p = s.k.compress(s.k.pt)
        s.i = s.p[:8]
        s.c = root.k.sign(s.i) if root else None
        s.tp, s.tn = {}, []
        s.b = BASE
        s.root = root
        s.com = {s.i:s}
        s.un = {}

    def chresp(s, cand):
        assert cand not in s.un
        if ecc.b2i(cand[8:10]) == 0:
            s.un[cand] = True
            return s.p + s.k.sign(cand)
        for x in s.tp:
            if x[48:58] == cand:
                s.un[cand] = True
                return s.p + s.k.sign(cand)
        return
        
    def pay(s, dst, mt):
        s.com[dst.i] = dst
        b = BloomFilter(100, 0.1)
        assert len(b.dumps()) == BL_SIZE
        ack = None
        m0 = s.tn[-1] if s.tn else s.i + num(0) + ecc.i2b(0, 8) + mnt(0) + bal(s.b) + dat(0) + b.dumps() + hsh()
        if m0[10:18] in s.com: ack = s.com[m0[10:18]].chresp(s.i+m0[8:10])
        if m0[8:18] == Z10:    ack = s.root.chresp(s.i+m0[8:10])
        t = s.p + m0 + s.k.sign(m0)
        for x in s.tp:
            if s.tp[x] == True:
                k = x[48:58]
                assert '%s'%k not in b
                b += '%s'%k
                t += x
                s.tp[x] = False
        s.b -= mt
        la = dat(now())
        m = s.i + num(getn(m0)+1) + dst.i + mnt(mt) + bal(s.b) + la + b.dumps() + hsh(t) 
        s.tn.append(m)
        return s, t + dst.i + mnt(mt) + la + ack + s.k.sign(m)
    
    def get(s, param):
        orig, tt = param
        s.com[orig.i] = orig
        t, a = tt[:-SAJ], tt[-SAJ:]
        assert len(t)%SIZE == 0
        l = len(t)//SIZE
        p0, n0, src = None, None, None
        for i in range(l):
            m = t[i*SIZE:(i+1)*SIZE]
            p, e, g = m[:48], m[48:-96], m[-96:]
            if i == 0:
                p0, n0, e0, d0, b0 = p, getn(e), e, getd(e), BloomFilter.loads(e[-BL_SIZE-16:-16])
                src = e[:8]
            else:
                src = e[10:18]
                assert '%s'%e[:10] not in b0
                b0 += '%s'%e[:10]
            if e[:8] in s.com: assert s.root.k.verify(s.com[e[:8]].c, src) # certificate
            else: print ('income cert not verified', i)
            s.o.pt = s.o.uncompress(p)
            assert s.o.verify(g, e) # in signature
        m1 = src + num(n0+1) + s.i + a[8:12] + bal(getb(e0)-ecc.b2i(a[8:12])) + a[12:16] + b0.dumps() + hsh(t)
        #print (ddod(d0))
        assert ecc.b2i(a[12:16]) > d0
        ak = a[-192:-96]
        s.o.pt = s.o.uncompress(a[16:16+48])
        assert s.o.verify(ak, src+num(n0)) # ack signature
        s.o.pt = s.o.uncompress(p0)
        assert s.o.verify(a[-96:], m1) # final signature
        s.tp[p0 + m1 + a[-96:]] = True
        s.b += getm(m1)
        
if __name__ == '__main__':
    root = agent()
    (alice, bob, carol, dave, eve) = [agent(root) for x in range(5)]
    bob.get(alice.pay(bob, 80))
    ecc.time.sleep(1) # not same date
    bob.get(alice.pay(bob, 10))
    dave.get(alice.pay(dave, 30))
    carol.get(bob.pay(carol, 20))
    print (alice.b, bob.b, carol.b, dave.b, eve.b)
    assert alice.b+bob.b+carol.b+dave.b+eve.b == 5*BASE
        
# End ⊔net!
