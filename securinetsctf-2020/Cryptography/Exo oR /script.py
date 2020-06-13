import base64
import codecs
from pwn import xor


def Alpha(flag):
	enc = xor(flag[0],'\x13')
	for i in range(1,len(flag)):
		enc += xor(flag[i],enc[i-1])
	return enc


flag = "TODO"
encrypted = Alpha(flag)
encrypted = codecs.encode(encrypted, 'rot_13')

with open("encrypted.txt","w+") as f:
	f.write(base64.b64encode(encrypted))

"""

encrypted.txt : QCVTM04oUyNKJF8aLhp2EHYQQjcHaCpLdg5zMnMyc0wk

"""



