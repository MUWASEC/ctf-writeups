from pwn import p64
for possible in range(0x1041504000100000, 0x1041504000f00000):
    if (possible&0x3153524942555a41) == 0x1041504000455200:
        print(p64(possible))