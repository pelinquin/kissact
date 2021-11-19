#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" 
No strategy if Bloomfilter returns a false positive
"""

import ecc, bloomfilter
BL_SIZE = 70

def mnt(x):  return ecc.i2b(x, 4)
def getm(x): return ecc.b2i(x[18:22])
def bal(x):  return ecc.i2b(x, 4)
def getb(x): return ecc.b2i(x[22:26])
def num(x):  return ecc.i2b(x, 2)
def getn(x): return ecc.b2i(x[8:10])
def hsh(x=b''): return ecc.hashlib.sha256(x).digest()[:16]
def geth(x): return x[-16:]
def bl():return ecc.i2b(0, BL_SIZE)
def gbl(x):  return bloomfilter.BloomFilter.loads(gbr(x))
def gbr(x):  return x[126:126+BL_SIZE]
def ack(m='', w=None): return p[w].sign(m.encode('utf-8')) if w else ecc.i2b(0, 96)
def gack(x): return x[30:30+96]
def now():   return int(ecc.time.mktime(ecc.time.gmtime()))
def dat(d):  return ecc.i2b(d, 4)
def getd(x): return ecc.b2i(x[26:30])
def ddcod(t):return ecc.time.strftime('%d/%m/%y %H:%M:%S', ecc.time.localtime(float(ecc.b2i(t))))

def check(n, frm, me, prv, r, m, s):
    for u in p: assert p['root'].verify(c[u], u.encode('utf-8')) # certificates
    assert i[frm] == m[0][:8] and i[frm] == m[3][:8] and i[me] == m[3][10:18] # id
    assert p[prv].verify(gack(m[3]), b'#%d'%n + me.encode('utf-8')) # ack
    assert p[frm].verify(s[0], m[0]) # signature out
    for j in range(len(r)): assert p[r[j][0]].verify(s[j+1], m[j+1]) # signature in
    assert p[frm].verify(s[3], m[3]) # signature out
    assert getb(m[0]) + getm(m[1]) + getm(m[2]) - getm(m[3]) == getb(m[3]) # balance
    assert hsh(m[0] + m[1] + m[2] + m[3][:-16]) == m[3][-16:] # hash
    assert getn(m[3]) == getn(m[0]) + 1 # block num
    assert getd(m[0]) < getd(m[3]) # date outcomes
    assert getd(m[1]) < getd(m[2]) # date incomes
    b = gbl(m[0])
    for j in ('%s%d'%r[0], '%s%d'%r[1]):
        assert j not in b
        b.put(j)
    assert b.dumps() == gbr(m[3])

def build(n, me, dst, prv, r):
    m, s = [b'']*4, [b'']*4
    b = bloomfilter.BloomFilter(100, 0.1)
    m[0] = i[me] + num(n) + i[prv] + mnt(30) + bal(70) + dat(22) + ack() + b.dumps() + hsh()
    m[1] = i[r[0][0]] + num(r[0][1]) + i[me] + mnt(15) + bal(24) + dat(35)  + ack() + bl() + hsh()
    m[2] = i[r[1][0]] + num(r[1][1]) + i[me] + mnt(20) + bal(56) + dat(576) + ack() + bl() + hsh()
    for j in ('%s%d'%r[0], '%s%d'%r[1]):
        assert j not in b
        b.put(j)
    tmp = i[me] + num(n+1) + i[dst] + mnt(90) + bal(15) + dat(now()) + ack('#%d%s' %(n+1, dst), prv) + b.dumps()
    m[3] = tmp + hsh(m[0]+m[1]+m[2]+tmp)
    s[0] = p[me].sign(m[0])
    s[1] = p[r[0][0]].sign(m[1])
    s[2] = p[r[1][0]].sign(m[2])
    s[3] = p[me].sign(m[3])
    return m, s

SIZE = 48 + 22 + 96
SAJ = 8 + 4 + 96

class agent:
    def __init__(s, root=None):
        s.k, s.o = ecc.ecdsa(), ecc.ecdsa()
        s.k.generate()
        s.p = s.k.compress(s.k.pt)
        s.i = s.p[:8]
        s.c = root.k.sign(s.i) if root else None
        s.n = 0
        s.tp, s.tn = {}, []
        s.b = 100
        s.root = root
    def pay(s, dst, mt):
        m = s.i + num(s.n) + ecc.i2b(0, 8) + mnt(0)
        t = s.p + m + s.k.sign(m)
        #
        m = ecc.i2b(0, 8) + num(s.n) + s.i + mnt(10)
        t += s.p + m + s.k.sign(m)
        #
        for x in s.tp:
            if s.tp[x] == True:
                print ('yes')
                t += x
                s.tp[x] = False
        m = s.i + num(s.n+1) + dst.i + mnt(mt)
        s.b -= mt
        s.tn.append(s.p + m + s.k.sign(m))
        return t + dst.i + mnt(mt) + s.k.sign(m)
    def get(s, src, tt):
        t, a = tt[:-SAJ], tt[-SAJ:] 
        assert len(t)%SIZE == 0
        l = len(t)//SIZE
        p0 = None
        for i in range(l):
            m = t[i*SIZE:(i+1)*SIZE]
            p, e, g = m[:48], m[48:-96], m[-96:]
            if i == 0 :
                p0, n0 = p, getn(e)
                assert src.i == e[:8]
            else: assert src.i == e[10:18]
            assert s.root.k.verify(src.c, src.i) # certificate
            s.o.pt = s.o.uncompress(p)
            assert s.o.verify(g, e) # signature
        m = src.i + num(n0+1) + s.i + a[8:12]
        s.o.pt = s.o.uncompress(p0)
        assert s.o.verify(a[-96:], m) # signature
        s.b += getm(m)
        s.tp[m] = True
        
if __name__ == '__main__':

    root = agent()
    (alice, bob, carol, dave, eve) = [agent(root) for x in range(5)]
    bob.get(alice, alice.pay(bob, 90))
    carol.get(eve, eve.pay(carol, 20))
    print (alice.b, bob.b, carol.b, dave.b, eve.b)

    ##### SPARE
    p, c, i = {}, {}, {}
    for u in ('root', 'alice', 'bob', 'carol', 'dave', 'eve'):
        p[u] = ecc.ecdsa()
        p[u].generate()
        c[u], i[u] = p['root'].sign(u.encode('utf-8')), p[u].compress(p[u].pt)[:8]
    n, me, dst, prv, r = 412, 'alice', 'bob', 'eve', (('carol', 188), ('dave', 245))
    m, s = build(n, me, dst, prv, r)
    check(n+1, me, dst, prv, r, m, s)
        
# End ⊔net!


