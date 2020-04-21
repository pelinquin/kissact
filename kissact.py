""" KISSACT  - Keep Stupid Simple Automatic Contact Tracing
 (Less than 100 lines of Python code)
 12 bytes EphIds + 3 bytes Prefix + 1 byte Price: 16bytes BLEid 
https://github.com/pelinquin/kissact
"""
import hashlib, secrets

PREFIX = b'\xc0\xdd\x19'

def contact(u1, u2, duration=1, proxi=1, price=0):
        " Filtering on PREFIX in the real app "
        u1.cts[u2.ids[-1]] = (len(u1.ids), duration, proxi)
        u2.cts[u1.ids[-1]] = (len(u1.ids), duration, proxi)
        u1.balance += price
        u2.balance -= price

class ctApp:

        def __init__(self, name):
                self.name, self.score, self.balance = name, [], 0
                self.root = secrets.token_bytes(12) + PREFIX + b'\0'
                self.ids, self.cts = [], {}

        def next(self):
                oldid = self.root if self.ids == [] else self.ids[-1]
                self.ids.append(hashlib.sha256(oldid).digest()[:12])

        def log(self):
                print ('USER', self.name, 'Balance:', self.balance, 'Said:', len(self.ids))
                for i, j in enumerate(self.ids): print (' ',i+1, j)
                print ('USER', self.name, 'Heard:', len(self.cts))
                for x in self.cts: print (' ', x, self.cts[x])

        def test(self, s):
                for i in [x for x in s.get() if x in self.cts]: self.score.append(self.cts[i])
                print (self.name, len(self.ids), self.balance, self.score)
                        
class ctServer:

        def __init__(self):
                self.inf = []

        def declare(self, ids, root=None, l=0):
                for x in ids: self.inf.append(x)
                if root:
                        for i in range(l):
                                oldid = root if ids == [] else ids[-1]
                                ids.append(hashlib.sha256(oldid).digest()[:12])
                                self.inf.append(ids[-1])
        def get(self):
                return self.inf

        def next_epoch(self, u, steps):
                for i in range(steps):
                        for x in u: x.next()
        def test(self, u):
                for x in u: x.test(self)

        def log(self, u):
                for x in u: x.log()

if __name__ == "__main__":

        print (__doc__)
        u, s = (ctApp('Alice'), ctApp('Bob'), ctApp('Carol'), ctApp('David')), ctServer()

        s.next_epoch(u, 2)
        contact(u[0], u[1], 100, 2)
        s.next_epoch(u, 3)
        contact(u[1], u[2], 50, 20)
        s.next_epoch(u, 3)
        contact(u[1], u[2], 300, 40, 20)
        s.next_epoch(u, 5)
        s.declare(u[2].ids)                     # Carol is sick and gives his EphIds
        s.declare([], u[3].root, len(u[0].ids)) # David is sick and gives his root key
        s.next_epoch(u, 5)    
        s.log(u)
        s.test(u)
# end
