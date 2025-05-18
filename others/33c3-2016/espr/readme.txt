# desc
(https://archive.ccc.ac/33c3ctf.ccc.ac/uploads/espr_small.jpg)[ESPR]

nc 78.46.224.86 1337

# solution
> stack.dmp
    > at 42 indicate pie is disabled
> elf.dmp
    > non-pie start from 0x400000
    > get offset of function global offset table
> on current challenge it's possible to overwrite printf@got to libc system, but on modern glibc it's not possible due to stack allignment check
    > call gets@plt will put rop payload on stack/$rsp
    > overwrite printf@got to pop_ret, this will pop return address of call printf@plt and execute our rop payload
    > do ret2libc