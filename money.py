#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" 
Usage: ./money.py -> run simple case
Purpose: Transpose on iOs using ble
(!) No strategy if Bloomfilter returns a false positive
Can one change BloomFilter setup dynamically ? 
<src:8><num:2><dst:8><mnt:4><bal:4><dat:4><bl:BSIZ><hash:16>
"""

import ecc
from simplebloom import BloomFilter

BSIZ = 92
Z10  = ecc.i2b(0, 10)
SIZE = 96 + 48 + 46 + BSIZ + 96 # pk+msg+bl+sign
SAJ  = 8 + 4 + 4 + 144 + 96     # id+mnt+dat+ack+sign
BASE = 1000

def mnt(x):  return ecc.i2b(x, 4)
def getm(x): return ecc.b2i(x[18:22])
def bal(x):  return ecc.i2b(x, 4)
def getb(x): return ecc.b2i(x[22:26])
def num(x):  return ecc.i2b(x, 2)
def getn(x): return ecc.b2i(x[8:10])
def hsh(x):  return ecc.hashlib.sha256(x).digest()[:16]
def now():   return int(ecc.time.mktime(ecc.time.gmtime()))
def dat(d):  return ecc.i2b(d, 4)
def getd(x): return ecc.b2i(x[26:30])
def ddod(t): return ecc.time.strftime('%d/%m/%y %H:%M:%S', ecc.time.localtime(float(t)))

class agent:
    
    def __init__(s, root=None):
        s.k, s.o, s.b, s.root = ecc.ecdsa(), ecc.ecdsa(), BASE, root
        s.k.generate()
        s.p = s.k.compress(s.k.pt)
        s.i = s.p[:8]
        s.c = root.k.sign(s.i) if root else None
        s.tp, s.tn, s.com, s.un = {}, [], {s.i:s}, {}

    def chresp(s, cand):
        assert cand not in s.un
        if ecc.b2i(cand[8:10]) == 0:
            s.un[cand] = True
            return s.p + s.k.sign(cand)
        for x in [y for y in s.tp if y[144:154] == cand]:
            s.un[cand] = True
            return s.p + s.k.sign(cand)
        return
        
    def pay(s, dst, mt):
        s.com[dst.i] = dst
        b, ack, la = BloomFilter(100, 0.1), None, dat(now())
        assert len(b.dumps()) == BSIZ
        m0 = s.tn[-1] if s.tn else s.i + num(0) + ecc.i2b(0, 8) + mnt(0) + bal(s.b) + dat(0) + b.dumps() + hsh(b'')
        if m0[10:18] in s.com: ack = s.com[m0[10:18]].chresp(s.i+m0[8:10])
        if m0[8:18] == Z10:    ack = s.root.chresp(s.i+m0[8:10])
        t = s.c + s.p + m0 + s.k.sign(m0)
        for x in [y for y in s.tp if s.tp[y] == True]:
            e, s.tp[x] = x[144:], False
            assert '%s'%e[:10] not in b
            b += '%s'%e[:10]
            t += x
        s.b -= mt
        m = s.i + num(getn(m0)+1) + dst.i + mnt(mt) + bal(s.b) + la + b.dumps() + hsh(t) 
        s.tn.append(m)
        return t + dst.i + mnt(mt) + la + ack + s.k.sign(m)
    
    def get(s, tt):
        print(len(tt)) # min 634
        t, a = tt[:-SAJ], tt[-SAJ:]
        assert len(t)%SIZE == 0
        for i in range(len(t)//SIZE):
            m = t[i*SIZE:(i+1)*SIZE]
            c, p, e, g = m[:96], m[96:144], m[144:-96], m[-96:]
            if i == 0: c0, p0, e0, b, src= c, p, e, BloomFilter.loads(e[-BSIZ-16:-16]), e[:8]
            else:
                assert src == e[10:18] and '%s'%e[:10] not in b
                b += '%s'%e[:10]
            assert s.root.k.verify(c, e[:8]) # certificate
            s.o.pt = s.o.uncompress(p)
            assert s.o.verify(g, e) # in signature
        m1 = src + num(getn(e0)+1) + s.i + a[8:12] + bal(getb(e0)-ecc.b2i(a[8:12])) + a[12:16] + b.dumps() + hsh(t)
        assert ecc.b2i(a[12:16]) > getd(e0)
        ak = a[-192:-96]
        s.o.pt = s.o.uncompress(a[16:16+48])
        assert s.o.verify(ak, src+num(getn(e0))) # ack signature
        s.o.pt = s.o.uncompress(p0)
        assert s.o.verify(a[-96:], m1) # final signature
        s.tp[c0 + p0 + m1 + a[-96:]] = True
        s.b += getm(m1)
        
if __name__ == '__main__':
    root = agent()
    (alice, bob, carol, dave, eve) = [agent(root) for x in range(5)]
    bob.get(alice.pay(bob, 50))
    ecc.time.sleep(1) # not same date
    bob.get(alice.pay(bob, 10))
    ecc.time.sleep(1) # not same date
    bob.get(alice.pay(bob, 20))
    dave.get(alice.pay(dave, 30))
    carol.get(bob.pay(carol, 20))
    eve.get(carol.pay(eve, 15))
    assert alice.b+bob.b+carol.b+dave.b+eve.b == 5*BASE
        
# End ⊔net!
