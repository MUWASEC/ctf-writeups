from pwn import *
p = remote('172.17.0.2', 1337)
with open('./poc.js', 'r') as fd:
    for data in fd.readlines():
        p.sendline(data.strip())
p.sendline('EOF')
p.interactive()