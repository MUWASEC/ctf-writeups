Can you pwn these two binaries at the same time?

Your goal is to make them execute execve("/bin/sh", ...). Good luck!

nc parallel2.tghack.no 6006

or use a mirror closer to you:

    nc us.parallel2.tghack.no 6006 (US)

    nc asia.parallel2.tghack.no 6006 (Japan)
    quarantine
    quarantine32
    64-bit libc
    32-bit libc

Some hints/clarifications:

    if one of the processes crashes, you lose
    the output is prefixed with an ID, either 0 or 1
        for example: 0: hello, world!\n
    if one process executes execve("/bin/sh", ...);, it will freeze and you can ignore it
