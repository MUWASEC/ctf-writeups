# desc
I doubt it's harder.

nc 128.199.152.175 10001

# solution
> with only read function call and no FULL-RELRO we can overwrite 1 byte of read@got so it pointing to syscall gadget
> later we use it to call syscall write to leak libc address on .got section and do ret2libc
> idk about remote server but on local, read function will expect \n to process the input
    > i decide to do ret2csu with syscall gadget, with this approach i can easily control rax/rdx
> i create 2 approach
    > one with full rop 32-bit calling convention (it's the first/old solver that i made back when i still learning shits)
    > one with ret2csu (new solver, compatible with modern library/machine)