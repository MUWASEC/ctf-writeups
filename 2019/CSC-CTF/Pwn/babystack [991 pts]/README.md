Description:  
`nc babystack.problem.cscctf.com 11111`


author: stürmisch

Hint:

Solution:  
`>` binary is 32-bit ELF with no pie/canary/relro and only call `read()` function  
`>` limited rop gadget, decide to do classic **`ret2dlresolve`** (*o great pwntools, i am to lazy too do manual ret2dl solution*)