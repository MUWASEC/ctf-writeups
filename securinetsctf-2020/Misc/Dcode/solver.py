from pwn import *
import string, base64

def hex_to_string(s):
    try:
        res = str(s).decode('hex')
        if 'Securinets' in res:
            return res
        else:
            return False
    except:
        return False
        
def bin_to_str(s):
    try:
        res = "{0:0>4X}".format(int(str(s), 2)).decode('hex')
        if 'Securinets' in res:
            return res
        else:
            return False
    except:
        return False

def rot13(s):
    try:
        map_rot13 = string.maketrans( 
            "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", 
            "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")
        res = string.translate(s, map_rot13)
        if 'Securinets' in res:
            return res
        else:
            return False
    except:
        return False

def _b64(s):
    try:
        res = base64.b64decode(s)
        if 'Securinets' in res:
            return res
        else:
            return False
    except:
        return False

def _b32(s):
    try:
        res = base64.b32decode(s)
        if 'Securinets' in res:
            return res
        else:
            return False
    except:
        return False

tools=[hex_to_string, bin_to_str, rot13, _b32, _b64]
p = remote('34.226.120.3', 30004)
for x in xrange(101):
    p.recvuntil('Ciphertext:\n')
    c = p.recvline().strip()
    for i in range(len(tools)):
        res = tools[i](c)
        if res:
            print(res)
            p.sendlineafter('>', res)
            break
        else:
            if i == len(tools)-1:
                print(c)
                exit(0)
p.interactive()
#Securinets{Y0u're_th3_gr34te$t_dc0deR!}