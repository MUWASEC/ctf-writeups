import pwn
import time
import subprocess
import string
#nc 104.199.120.115 7787

while True:
    pr = pwn.remote("104.199.120.115", 7787)

    pr.read()

    print(str(int(time.time())))

    output = subprocess.check_output(['./seed', str(int(time.time()))])

    tosend = ""
    for i in output.splitlines():
        tosend += hex(int(i))[2:]
    print(tosend.upper())
    pr.sendline(tosend.upper())
    out = pr.recv(4096)
    if "I need hex" not in out and all(map(lambda x: x in string.printable, out)):
        print(out)
        exit(0)
