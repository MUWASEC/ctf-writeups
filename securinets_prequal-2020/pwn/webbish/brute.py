from pwn import *
i=1
while True:
    with context.local(log_level='error'):
        try:
            payload = "\"''\""*i
            p = process('./main')
            p.sendline(payload)
            if 'username' in p.recvline().strip():
                print i,
                p.close()
                i+=1
        except:
            pass
            break
            
            