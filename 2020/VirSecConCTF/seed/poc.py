from pwn import *
from ctypes import CDLL

libc = ctypes.cdll.LoadLibrary('./libc6_2.23-0ubuntu10_amd64.so')
#libc = CDLL('/usr/lib64/libc.so.6')

#t=libc.time(0)
t=1585951380
with context.local(log_level = 'error'):
    while True:
        try:
            libc.srand(t)
            addr = libc.rand() & 0xf
            t+=1
            p = remote('jh2i.com', 50010)
            #p = process('seed_spring')
            p.sendlineafter('height:', str(addr))
            if 'WRONG' not in p.recvline():
                print t,
                for i in xrange(29):
                    addr = libc.rand() & 0xf
                    print addr,
                    p.sendlineafter('height:', str(addr))
                    if 'WRONG' in p.recvline():
                        p.close()
                        continue
                print t
                p.interactive()
                break
            p.close()
            
        except:
            print()
            p.close()