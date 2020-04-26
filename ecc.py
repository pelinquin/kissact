#!/usr/bin/python3
# -*- coding: utf-8 -*-

" Simple Signature/verification for ecdsa P-384 curve + z85encoding "

import os, sys, urllib.parse, hashlib, base64, struct, time

PAD = lambda s:(len(s)%2)*'0'+s[2:]

def i2b(x, n=1):
    z = bytes.fromhex(PAD(hex(x)))
    return ((n-len(z))%n)*bytes.fromhex('00') + z

z1  = i2b(0, 1)
v1  = i2b(1, 1)
z2  = i2b(0, 2)
z4  = i2b(0, 4)
z8  = i2b(0, 8)
z10 = i2b(0, 10)
z16 = i2b(0, 16)

def b2i(x):
    return int.from_bytes(x, 'big')

def b2h(x):
    return x.hex().encode('UTF-8')

def h2b(x):
    return bytes.fromhex(x.decode('UTF-8'))

def s2b(x, n=1):
    "signed int to bytes with n padding"
    z = bytes.fromhex(PAD(hex(x + (1<<(8*n-1)))))
    return ((n-len(z))%n)*bytes.fromhex('00') + z

zs4 = s2b(0, 4)

def b2s(x, n=1):
    "signed bytes to int"
    return int.from_bytes(x, 'big') - (1<<(8*n-1))

def H(*tab):
    return int(hashlib.sha384(b''.join(tab)).hexdigest(), 16)

def datencode(n=0):
    "4 chars (minute precision)"
    return i2b(int(time.mktime(time.gmtime())/60 + 60*24*n), 4)

def datint(n=0):
    "int (minute precision)"
    return int(time.mktime(time.gmtime())/60 + 60*24*n)

def datdecode(tt):
    "4 chars (minute precision)"
    return time.strftime('%d/%m/%y %H:%M', time.localtime(float(b2i(tt)*60)))

def is_after(d1, d2): 
    "_"
    return b2i(d1) > b2i(d2)

def add1year(d):
    return i2b(b2i(d) + 525600, 4)

_p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
_r  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
_b  = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
_Gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
_Gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f

class Curve(): 
    def __init__(self, p, a, b): self.p, self.a, self.b = p, a, b

c384 = Curve(_p, -3, _b)

class Point():
    def __init__(self, curve, x, y, order = None):
        self.curve, self.x, self.y, self.order = curve, x, y, order
    def __add__(self, other):
        if other == INFINITY: return self
        if self == INFINITY: return other
        if self.x == other.x:
            if (self.y + other.y) % self.curve.p == 0: return INFINITY
            else: return self.double()
        p = self.curve.p
        l = ((other.y - self.y) * pow(other.x - self.x, p-2, p)) % p
        x3 = (l*l - self.x - other.x) % p
        y3 = (l*(self.x - x3) - self.y) % p
        return Point(self.curve, x3, y3)
    def __mul__(self, e):
        if self.order: e = e % self.order
        if e == 0 or self == INFINITY: return INFINITY
        e3, neg_self = 3*e, Point(self.curve, self.x, -self.y, self.order)
        i = 1 << (len(bin(e3))-4)
        result = self
        while i > 1:
            result = result.double()
            if (e3 & i) != 0 and (e & i) == 0: result = result + self
            if (e3 & i) == 0 and (e & i) != 0: result = result + neg_self
            i //= 2
        return result
    def __rmul__(self, other): return self * other
    def double(self):
        if self == INFINITY: return INFINITY
        p, a = self.curve.p, self.curve.a
        l = ((3 * self.x * self.x + a) * pow(2 * self.y, p-2, p)) % p
        x3 = (l*l - 2 * self.x) % p
        y3 = (l*(self.x - x3) - self.y) % p
        return Point(self.curve, x3, y3)
    def is_on(self):
        return (self.y*self.y)%self.curve.p == (self.x*self.x*self.x - 3*self.x + self.curve.b)%self.curve.p

INFINITY = Point(None, None, None)  

class ecdsa:
    def __init__(self):
        self.gen = Point(c384, _Gx, _Gy, _r)
        self.pkgenerator, self.pkorder = self.gen, self.gen.order

    def generate(self):
        while True:
            secexp = randrange(self.gen.order)
            pp = self.gen*secexp
            if (pp.y&1): break
        self.pt, n = pp, self.gen.order
        if not n: raise 'Generator point must have order!'
        if not n * pp == INFINITY: raise 'Bad Generator point order!'
        if pp.x < 0 or n <= pp.x or pp.y < 0 or n <= pp.y: raise 'Out of range!'
        self.privkey = secexp
        assert (self.pt.is_on())
        
    def verify(self, sig, data):
        r, s, G, n = b2i(sig[:48]), b2i(sig[48:]), self.pkgenerator, self.pkorder
        if r < 1 or r > n-1 or s < 1 or s > n-1: return False
        c = pow(s, n-2, n)
        u1, u2 = (H(data) * c) % n, (r * c) % n
        z = u1 * G + u2 * self.pt
        return z.x % n == r

    def sign(self, data):
        rk, G, n = randrange(self.pkorder), self.pkgenerator, self.pkorder
        k = rk % n
        p1 = k * G
        r = p1.x
        s = (pow(k, n-2, n) * (H(data) + (self.privkey * r) % n)) % n
        return i2b(r, 48) + i2b(s, 48)

    def compress(self, rk):
        return i2b(rk.x, 48);

    def uncompress(self, key):
        nk = Point(c384, b2i(key), _Gy, _r)
        t = pow(nk.x*nk.x*nk.x - 3*nk.x + _b, (_p+1)//4, _p)
        nk.y = t if t&1 else (-t)%_p
        return nk 
    
    def compress56(self, rk):
        return z56encode(i2b(rk.x, 48));

    def uncompress56(self, key):
        nk = Point(c384, b2i(z56decode(key)), _Gy, _r)
        t = pow(nk.x*nk.x*nk.x - 3*nk.x + _b, (_p+1)//4, _p)
        nk.y = t if t&1 else (-t)%_p
        return nk 

    def compress85(self, rk):
        return z85encode(i2b(rk.x, 48));

    def uncompress85(self, key):
        nk = Point(c384, b2i(z85decode(key)), _Gy, _r)
        t = pow(nk.x*nk.x*nk.x - 3*nk.x + _b, (_p+1)//4, _p)
        nk.y = t if t&1 else (-t)%_p
        return nk 

def randrange(order):
    b = (1+len('%x' % order))//2
    c = b2i(os.urandom(b))
    return c//2 if c >= order else c

Z85C = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'
Z56C = b'23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz'

Z56M = {c:i for i, c in enumerate(Z56C)}
Z85M = {c:i for i, c in enumerate(Z85C)}
_85s = [85**i for i in range(5)][::-1]
_56s = [56**i for i in range(6)][::-1]

assert len(Z56C)  == len(Z56M)  == 56
assert len(Z85C)  == len(Z85M)  == 85

def z56encode(raw):
    nv, res = len(raw)//4, []
    for v in struct.unpack('>%dI' % nv, raw):
        for ofs in _56s:
            res.append(Z56C[(v // ofs) % 56])
    return bytes(res)

def z56decode(zb):
    nv, res = len(zb)//6, []
    for i in range(0, len(zb), 6):
        val = 0
        for j, ofs in enumerate(_56s):
            val += Z56M[zb[i+j]] * ofs
        res.append(val)
    return struct.pack('>%dI' % nv, *res)

def z85encode(raw):
    nv, res = len(raw)//4, []
    for v in struct.unpack('>%dI' % nv, raw):
        for ofs in _85s:
            res.append(Z85C[(v // ofs) % 85])
    return bytes(res)

def z85decode(zb):
    nv, res = len(zb)//5, []
    for i in range(0, len(zb), 5):
        val = 0
        for j, ofs in enumerate(_85s):
            val += Z85M[zb[i+j]] * ofs
        res.append(val)
    return struct.pack('>%dI' % nv, *res)

if __name__ == '__main__':
    for i in range (-1000, 1000): assert i == b2s(s2b(i, 4), 4)
    for i in range(10):
        k, m0, m1 = ecdsa(), bytes('blabla %d' % i, 'utf-8'), b'other_message'
        assert m0 == z85decode(z85encode(m0)) == z56decode(z56encode(m0))
        print (z85encode(m0), z56encode(m0))
        k.generate()
        pub = k.compress(k.pt)
        print ('PubK', pub[:8])
        k.pt = k.uncompress(pub)
        s = k.sign(m0)
        print ('Sign', b2h(s),       len(b2h(s))       )
        print ('Sign', z56encode(s), len(z56encode(s)) )
        print ('Sign', z85encode(s), len(z85encode(s)) )
        assert (k.verify(s, m0) and not k.verify(s, m1))

# End ⊔net!
