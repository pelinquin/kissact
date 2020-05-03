#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" Usage: ./beacon.py 5000 & ./beacon.py 5001
Create a ./db directory for dbm results
"""

import socket, threading, sys, secrets, pynput, dbm, ecc

BASP = 5000        # Base port number
MAXC = 10          # Max contacts
HOST = '127.0.0.1' # IP
TICK = 1           # in seconds
EPOC = 10          # in ticks

class beacon:
    ear, say, go = {}, {}, True
    def __init__(self, arg):
        self.p, s = int(arg), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        threading.Thread(target=self.server).start()
        pynput.keyboard.Listener(on_press=self.on_press).start()
        m, n, i = arg.encode('UTF-8') + secrets.token_bytes(12), now(), 0
        with dbm.open('db/s%s' % self.p, 'c') as b: # said ids
            while (True):
                if now() - n >= TICK:
                    n, i = now(), i + 1
                    if not i%EPOC: m = arg.encode('UTF-8') + secrets.token_bytes(12)
                    for x in [y for y in range(MAXC) if self.p!=BASP+y]:
                        z = self.say[m]+1 if m in self.say else 0
                        self.say[m], b[m] = z, ecc.i2b(i, 4) + ecc.i2b(z, 4)
                        s.sendto(m, (HOST, BASP+x))

    def on_press(self, key):
        try:
            self.go = not self.go
        except AttributeError:
            pass
        
    def server(self):
        s, n, buf = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), now(), {}
        s.bind((HOST, self.p))
        with dbm.open('db/h%s' % self.p, 'c') as b: # heard ids
            while (True):
                m = s.recvfrom(1024)[0]
                if now() - n <= 4: buf[m] = True
                else: n, buf = now(), {}
                z = self.ear[m]+1 if m in self.ear else 0
                self.ear[m], b[m] = z, ecc.i2b(now(), 4) + ecc.i2b(z, 4)
                print (m, z, len(buf))

def now():
    return int(ecc.time.mktime(ecc.time.gmtime()))

if __name__ == '__main__':
    if len(sys.argv) == 2: b = beacon(sys.argv[1])
    else: print (__doc__)

# End ⊔net!
