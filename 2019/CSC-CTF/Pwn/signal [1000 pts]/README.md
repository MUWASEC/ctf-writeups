Description:  
`nc signal.problem.cscctf.com 11112`

author: stürmisch

Hint:  
`__libc_csu_init`

Solution:  
`>` the hint is already obvious, 64-bit elf + buffer overflow bug with only call `read()` function  
`>` overwrite lsb address of `read@got` so it point to `syscall`  
`>` then do **`ret2csu`** to set $rax to `execve_syscall` number which is 0x3b, then another **`ret2csu`** to call execve syscall