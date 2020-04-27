#!/usr/bin/env python3
""" 
 KISSACT - Keep Stupid Simple Automatic Contact Tracing - https://github.com/pelinquin/kissact
"""

import secrets, random, operator, ecc
PREFIX  = b'\x19'
MAXDEBT = 100

def contact(u1, u2, duration=1, proximity=1, price=0):
    " 1B:PREFIX + 12B:EphIds + 2B:Hash + 1B:Price -> 16B BLEid "
    if price > 0:  # Generalized transaction with ECOTAX: 20%
        u1.ids[-1][0] = u1.ids[-1][0][:-3] + u2.ids[-1][0][1:3] + ecc.i2b(price, 1)
        u2.bal, u1.bal = u2.bal + price*4//5, u1.bal - price
        u1.note[u1.ids[-1][0]] = (u1.pk[:8], u1.k.sign(u1.ids[-1][0])) # (public id, signature)
        u2.refe[u1.ids[-1][0]] = u2.pk[:8] # or False
    u1.cts[u2.ids[-1][0]] = (len(u1.ids), duration, proximity)
    u2.cts[u1.ids[-1][0]] = (len(u1.ids), duration, proximity)
    u1.ids[-1][1][2] = u2.ids[-1][1][2] = True 

class ctApp:
    " app simulation class "
    def __init__(self, name, age=18):
        " Name is not required for the real app "
        self.name, self.age, self.hist, self.bal, self.eco = name, age, [], 0, 0
        self.root = PREFIX + secrets.token_bytes(12) + b'\0'*3
        self.ids, self.cts, self.risk, self.note, self.refe = [], {}, 0, {}, {}
        self.coef, self.k = (14, 1, 60, 1.2, 100), ecc.ecdsa()
        self.k.generate()
        self.pk = self.k.compress(self.k.pt)

    def next(self):
        " Latlong may be used locally only and never shared "
        lt, lg = random.randint(100, 200), random.randint(100, 200)
        oldi = self.root if self.ids == [] else self.root + self.ids[-1][0] 
        self.ids.append([PREFIX + ecc.hashlib.sha256(oldi).digest()[:12] + ecc.i2b(0,3), [lt, lg, False]])

    def log(self):
        " Just for debugging "
        print ('USER', self.name, 'Raw-balance:', self.bal, 'Said:', len(self.ids), 'ids')
        for i, j in enumerate(self.ids): print ('%02d'%(i+1), ecc.b2h(j[0][1:]),j[1:])
        print ('USER', self.name, 'Heard:', len(self.cts), 'ids')
        for x in self.cts: print ('  ', ecc.b2h(x[1:]), self.cts[x])

    def pretest(self, s):
        for x in self.note.keys(): s.hse[0][x] = self.note[x]
        for x in self.refe.keys(): s.hse[1][x] = self.refe[x]

    def test(self, s):
        " Updates parametric model "
        self.coef, bal = s.coef, self.bal + s.tax//len(s.pks)
        for i in [x for x in s.get() if x in self.cts]: self.hist.append(self.cts[i])
        print ('%s: %2d contacts, %2d contacts+, balance:%d'% (self.name, len(self.cts), len(self.hist), bal))
        self.model()
                
    def model(self):
        " Epidemiologists should define all parameters values "
        for x in self.hist:
            if x[0] - len(self.ids) > -self.coef[0]: self.risk += self.coef[1] + x[1]*x[2]//100
        if self.age > self.coef[2]: self.risk *= self.coef[3]
        print (self.name, 'risk-score:', self.risk)
        if self.risk > self.coef[4]:
            print (' has to 1/wear-a-mask 2/ask-to-be-tested 3/go-to-quarantine !')

    def filter(self, strong=False):
        " Strong means only ids with contacts are given "
        fids = []
        for x in self.ids:
            if not strong or (strong and x[1][2] == True): fids.append(x[0])
        return fids
                        
class ctServer:
    " Public backend "
    def __init__(self, param):
        self.inf, self.tick, self.coef, self.tax, self.pks = [], 0, param, 0, {}
        self.hse = [{}, {}]
    def register(self, u):
        for x in u: self.pks[x.k.compress(x.k.pt)] = True
    def declare(self, ids):
        for x in ids: self.inf.append(x)
    def get(self):
        return self.inf
    def next_epoch(self, u, steps):
        self.tick += steps
        for i in range(steps):
            for x in u: x.next()
    def test(self, u):
        for x in u: x.pretest(self)        
        self.tax, k, tab = sum([ecc.b2i(x[-1:])//5 for x in self.hse[0]]), ecc.ecdsa(), {}
        for x in u: x.test(self)
        assert operator.eq(self.hse[0].keys(), self.hse[1].keys()) # VERIF 1: no leaks
        assert sum([x.bal for x in u]) + self.tax == 0 # VERIF 2: sum balances null
        for x in self.hse[0]:
            for z in [y for y in self.pks if y[:8] == self.hse[0][x][0]]: k.pt = k.uncompress(z)
            assert k.verify(self.hse[0][x][1], x) # VERIF 3: Transaction signature ok
        for x in self.hse[0]:
            y, pr = self.hse[0][x][0], ecc.b2i(x[-1:])
            tab[y] = tab[y] + pr if y in tab else pr
        for z in [x for x in self.hse[1] if self.hse[1][x] in tab]: tab[self.hse[1][z]] -= ecc.b2i(z[-1:])
        for t in tab: assert tab[t] < MAXDEBT # VERIF 4: all debt under limit
            
    def log(self, u):
        print (__doc__, __file__, sum(1 for l in open(__file__)), 'lines')
        for x in u: x.log()


if __name__ == "__main__":
    " KISSACT simulation "
    u = (ctApp('Alice', 14), ctApp('Bob  ', 23), ctApp('Carol'), ctApp('David', 52))
    s = ctServer((14, 1, 60, 1.3, 90))      # epidemiologic parameters
    s.register(u)
    s.next_epoch(u, 2)                      # time is going 2 steps
    contact(u[0], u[1], 100, proximity=100) # Alice meet Bob
    s.next_epoch(u, 3)                      # 3 steps
    contact(u[1], u[2], 50, 20)             # Bob meet Carol
    s.next_epoch(u, 5)                      # 5 steps
    contact(u[2], u[1], 300, 40, price=20)  # Carol pays 20 to Bob
    s.next_epoch(u, 2)                      # 2 steps
    s.declare(u[2].filter(True))            # Carol is sick and gives a subset of her EphIds
    s.declare(u[3].filter())                # David is sick and gives all EphIds
    s.next_epoch(u, 4)                      # 4 steps
    contact(u[3], u[2], 100, 10, price=10)  # David pays 10 to Carol
    s.next_epoch(u, 1)                      # 1 step1
    contact(u[3], u[2], 100, 10, price=5)   # David pays 5 to Carol again
    s.next_epoch(u, 2)                      # 2 steps
    s.log(u)                                # log display
    s.test(u)                               # only Bob got a risk warning

# End ⊔net!
