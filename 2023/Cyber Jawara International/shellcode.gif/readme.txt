# desc
shellcode.gif 500

Author: Zafirr

You have shellcode, but it is fast enough?
139.59.234.75 3001 

# solution
program read input, put it in the mmap rwx buffer and call it using clone()
clone() is using CLONE_VM|CLONE_FILES flags and according to this phrack article http://phrack.org/issues/68/9.html#article
CLONE_VM mean parent and child process run in the same memory space
the only downside is that our register on clone() child will be empty, so no memory leak in the register

before our input in the buffer got executed as shellcode, some seccomp rules function is implemented
this will only effect child process
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x15 0x00 0x01 0x00000011  if (A != pread64) goto 0012
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x15 0x00 0x01 0x00000012  if (A != pwrite64) goto 0014
 0013: 0x06 0x00 0x00 0x00000000  return KILL
 0014: 0x15 0x00 0x01 0x00000013  if (A != readv) goto 0016
 0015: 0x06 0x00 0x00 0x00000000  return KILL
 0016: 0x15 0x00 0x01 0x00000014  if (A != writev) goto 0018
 0017: 0x06 0x00 0x00 0x00000000  return KILL
 0018: 0x15 0x00 0x01 0x00000065  if (A != ptrace) goto 0020
 0019: 0x06 0x00 0x00 0x00000000  return KILL
 0020: 0x15 0x00 0x01 0x000000bb  if (A != readahead) goto 0022
 0021: 0x06 0x00 0x00 0x00000000  return KILL
 0022: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0024
 0023: 0x06 0x00 0x00 0x00000000  return KILL
 0024: 0x15 0x00 0x01 0x0000010b  if (A != readlinkat) goto 0026
 0025: 0x06 0x00 0x00 0x00000000  return KILL
 0026: 0x15 0x00 0x01 0x00000127  if (A != preadv) goto 0028
 0027: 0x06 0x00 0x00 0x00000000  return KILL
 0028: 0x15 0x00 0x01 0x00000128  if (A != pwritev) goto 0030
 0029: 0x06 0x00 0x00 0x00000000  return KILL
 0030: 0x15 0x00 0x01 0x00000147  if (A != preadv2) goto 0032
 0031: 0x06 0x00 0x00 0x00000000  return KILL
 0032: 0x15 0x00 0x01 0x00000148  if (A != pwritev2) goto 0034
 0033: 0x06 0x00 0x00 0x00000000  return KILL
 0034: 0x06 0x00 0x00 0x7fff0000  return ALLOW


also after calling clone(), the main process decide to kill parent process after 5 sec. this mean we can't use shellcode that spawn
/bin/sh or shellcode that do reverse tcp because of 5 sec kill limitation and child process is running in the background
the other reason why this 5 sec limitation is matter is that according to Dockerfile content, we need to run readFlag program
located at /home/flag/ to get the flag and that program will sleep for 3 second

the problem right now is :
- full protection binary
- 5 sec runtime
- child process seccomp
- child process register have no memory address

the first problem we can use mprotect syscall to overwrite some opcode/assembly on main function
second one is not really a problem because we will redirect execution to parent process

for memory leak i've been thinking to read /proc/self/maps but syscall open is not permited in seccomp rule
the other method is using mmap syscall to leak libc address. tho i will not using this method because my Arch machine
is having a problem with vmmap padding
then it turns out there's pie and libc address in there (hint from probset)

so the solution step by step :
- leak pie address from our mmap child process and calculate elf base address
- using mprotect to make .text section into rwx page
- write execve shellcode right before "call kill" at main function
- win :3

learn something new today, this opcode "mov rsi, qword ptr fs:0x300" will leak stack address