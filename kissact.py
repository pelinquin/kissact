#!/usr/bin/env python3
""" 
 KISSACT  - Keep Stupid Simple Automatic Contact Tracing

 (100 lines of Python code)
 12 bytes EphIds + 3 bytes Prefix + 1 byte Price: 16bytes BLEid 
 https://github.com/pelinquin/kissact
"""
import hashlib, secrets, random
PREFIX = b'\xc0\xdd\x19'

def contact(u1, u2, duration=1, proximity=1, price=0):
        " Filtering on PREFIX in the real app "
        u1.cts[u2.ids[-1][0]] = (len(u1.ids), duration, proximity)
        u2.cts[u1.ids[-1][0]] = (len(u1.ids), duration, proximity)
        u1.ids[-1][1][2] = u2.ids[-1][1][2] = True 
        if price > 0: u1.balance, u2.balance = u1.balance + price, u2.balance - price

class ctApp:
        " app simulation class "
        def __init__(self, name, age=18):
                " Name is not required for the real app "
                self.name, self.age, self.hist, self.balance = name, age, [], 0
                self.root = secrets.token_bytes(12) + PREFIX + b'\0'
                self.ids, self.cts, self.risk = [], {}, 0
                self.coef = (14, 1, 60, 1.2, 100)

        def next(self):
                " Latlong may be used locally only and never shared "
                lt, lg = random.randint(100, 200), random.randint(100, 200)
                oldi = self.root if self.ids == [] else self.ids[-1][0]
                self.ids.append((hashlib.sha256(oldi).digest()[:12], [lt, lg, False]))

        def log(self):
                " Just for debugging "
                print ('USER', self.name, 'Balance:', self.balance, 'Said:', len(self.ids))
                for i, j in enumerate(self.ids): print ('%02d'%(i+1), j)
                print ('USER', self.name, 'Heard:', len(self.cts))
                for x in self.cts: print (' ', x, self.cts[x])

        def test(self, s):
                " Updates parametric model "
                self.coef = s.coef 
                for i in [x for x in s.get() if x in self.cts]: self.hist.append(self.cts[i])
                print ('%s with %2d contacts get balance:%d'% (self.name, len(self.hist), self.balance))
                self.model()
                
        def model(self):
                " Epidemiologist should defines all parameters "
                for x in self.hist:
                        if x[0] - len(self.ids) > -self.coef[0]: self.risk += self.coef[1] + x[1]*x[2]//100
                if self.age > self.coef[2]: self.risk *= self.coef[3]
                print (self.name, 'risk score:', self.risk)
                if self.risk > self.coef[4]:
                        print (' has to wear a mask and ask to be tested and to quarantine !')

        def filter(self, strong=False):
                " Strong means only contacts ids are given"
                fids = []
                for x in self.ids:
                        if not strong or (strong and x[1][2] == True): fids.append(x[0])
                return fids
                        
class ctServer:
        " Public backend "
        def __init__(self, param):
                self.inf, self.tick, self.coef = [], 0, param
                
        def declare(self, ids, root=None):
                for x in ids: self.inf.append(x)
                if root:
                        for i in range(self.tick):
                                oldid = root if ids == [] else ids[-1]
                                ids.append(hashlib.sha256(oldid).digest()[:12])
                                self.inf.append(ids[-1])
        def get(self):
                return self.inf

        def next_epoch(self, u, steps):
                self.tick += steps
                for i in range(steps):
                        for x in u: x.next()
                        
        def test(self, u):
                for x in u: x.test(self)

        def log(self, u):
                for x in u: x.log()

if __name__ == "__main__":
        " KISSACT simulation "
        print (__doc__)   
        u = (ctApp('Alice', 14), ctApp('Bob  ', 23), ctApp('Carol'), ctApp('David', 52))
        s = ctServer((14, 1, 60, 1.3, 90))      # epidemiologic parameters
        s.next_epoch(u, 2)                      # time is going 2 steps
        contact(u[0], u[1], 100, proximity=100) # Alice meet Bob
        s.next_epoch(u, 3)                      # 3 steps
        contact(u[1], u[2], 50, 20)             # Bob meet Carol
        s.next_epoch(u, 5)                      # 5 steps
        contact(u[2], u[1], 300, 40, 20)        # Carol pays 20 to Bob
        s.next_epoch(u, 2)                      # 2 steps
        s.declare(u[2].filter(True))            # Carol is sick and gives a subset of her EphIds
        s.declare([], u[3].root)                # David is sick and gives his root key
        s.next_epoch(u, 4)                      # 4 steps       
        s.log(u)                                # log display
        s.test(u)                               # only Bob got a risk warning
# end
