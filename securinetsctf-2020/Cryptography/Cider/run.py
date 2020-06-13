#!/usr/bin/python2.7
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from time import time
from base64 import b64encode
from secret import flag
import random


class MyAES:
	def __init__(self):
		self.key = self.generateKey()
		self.IV = "I_luv_Securinets"

	def pad(self,msg):
		x = (16 - len(msg) % 16)%16
		return (msg + chr(x)*x).encode()

	def generateKey(self):
		seed = int(time())
		random.seed(seed)
		return long_to_bytes(random.getrandbits(256))

	def encrypt(self,msg):
		cipher = AES.new(self.key,AES.MODE_CBC,self.IV)
		plain_pad = self.pad(msg)
		encrypted = cipher.encrypt(plain_pad)
		return b64encode(encrypted).decode()

def welcome():
	print("\nThey say AES is unbreakable. Can you decrypt this message ?\n\n")

def main():
	welcome()
	aes = MyAES()
	encrypted_flag = aes.encrypt(flag)
	print("Encrypted flag:")
	print(encrypted_flag)
	

if __name__ == '__main__':
    main()
