from pwn import *
elf = ELF('./math2', checksec=False)

# https://stackoverflow.com/a/22808285
def prime_factors(n):
    i = 2
    factors = []
    while i * i <= n:
        if n % i:
            i += 1
        else:
            n //= i
            factors.append(i)
    if n > 1:
        factors.append(n)
    res=''
    for pm in range(len(factors)):
        if pm==(len(factors)-1):
            res+='%s' % factors[pm]
        else:
            res+='%s ' % factors[pm]

    return res

p = elf.process()
#p = remote('ctf.joints.id', 17074)

p.recvline() # clear text
for i in range(0x63):
    num=eval(p.recvline().strip())
    pnum=prime_factors(num)
    #log.info('[%d] %d => %s' % (i, num, pnum)) # log
    p.sendlineafter(b'>', pnum.encode())
num=eval(p.recvline().strip())
pnum=prime_factors(num)
log.info('%d => %s' % (num, pnum)) # log

p.interactive()
