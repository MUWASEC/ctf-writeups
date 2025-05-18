Description:  
`nc twelver.problem.cscctf.com 11114`

author: stürmisch

Hint:  

Solution:  
`>` shellcode chall with seccomp filtering, where an initial instruction clears all CPU register values before execution begins  
`>` also didn't i mention we can only insert shellcode with length 12-byte lol ?  
`>>` **`seccomp rule`** `<<`
```c
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
 0008: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0010
 0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```
`>>` **`pre-instruction assembly`**  `<<`
```c
=> 0x7ffff7fbf000:      xor    rax,rax
   0x7ffff7fbf003:      xor    rbx,rbx
   0x7ffff7fbf006:      xor    rcx,rcx
   0x7ffff7fbf009:      xor    rdx,rdx
   0x7ffff7fbf00c:      xor    rsi,rsi
   0x7ffff7fbf00f:      xor    rdi,rdi
   0x7ffff7fbf012:      xor    rbp,rbp
   0x7ffff7fbf015:      xor    rsp,rsp
   0x7ffff7fbf018:      xor    r8,r8
   0x7ffff7fbf01b:      xor    r9,r9
   0x7ffff7fbf01e:      xor    r10,r10
   0x7ffff7fbf021:      xor    r11,r11
   0x7ffff7fbf024:      xor    r12,r12
   0x7ffff7fbf027:      xor    r13,r13
   0x7ffff7fbf02a:      xor    r14,r14
   0x7ffff7fbf02d:      xor    r15,r15
```
`>>` **`shellcode is limited to 12 bytes`**  `<<`
```c
│           0x00000c7a      488b45b8       mov rax, qword [buf]
│           0x00000c7e      4883c030       add rax, 0x30
│           0x00000c82      ba0c000000     mov edx, 0xc                ; size_t nbyte
│           0x00000c87      4889c6         mov rsi, rax                ; void *buf
│           0x00000c8a      bf00000000     mov edi, 0                  ; int fildes
│           0x00000c8f      e88cfcffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
```
`>` to solve this chall we can insert assembly (no more than 12 bytes) that loads additional shellcode which later do ORW (open-read-write) flag file  