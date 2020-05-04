#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" Usage: ./doctor.py brigiteduchmol@gmail.com
Change your email in the code
https://github.com/pelinquin/kissact
"""
import dbm, ecc

MY_EMAIL = 'doc@gmail.com'

def get_code(patient):
    with dbm.open('keys', 'c') as b:
        for x in b.keys():
            if b[x] == b'':
                b[x] = ('%s %s'%(MY_EMAIL, patient)).encode('UTF-8')
                return 'Give patient the code:\n%s %s %s '%(x.decode('UTF-8'), MY_EMAIL, patient)
    return 'no key left !'

if __name__ == '__main__':
    if len(ecc.sys.argv) == 2: print(get_code(ecc.sys.argv[1]))
    else: print (__doc__)
        
# End ⊔net!
