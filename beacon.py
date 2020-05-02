#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" Usage: ./beacon.py 5000 & ./beacon.py 5001 """

import socket, threading, sys, time, secrets
BASE_PORT = 5000
MAX_CONTACTS = 10
HOST = '127.0.0.1'

def server(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, p))
    while (True): print (s.recvfrom(1024)[0])

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    
    if len(sys.argv) == 2:
        threading.Thread(target=server, args=[int(sys.argv[1])]).start()
        while (True):
            c = sys.argv[1].encode('UTF-8') + secrets.token_bytes(12)
            time.sleep(1)
            for x in [y for y in range(MAX_CONTACTS+1) if int(sys.argv[1])!=BASE_PORT+y]:
                s.sendto(c, (HOST, BASE_PORT+x))
    else: print (__doc__)

# End ⊔net!
