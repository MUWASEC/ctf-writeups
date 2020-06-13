#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os, subprocess, time, random

faqs = {
	1: ['Translate this to ascii "2f6574632f706173737764"', '/etc/passwd'],
	2: [
	"""
	What returns this function with the parameters 0x4343, 0xff? Result starts with 0x\n

	_func:
		push   	ebp
		mov    	ebp,esp
		mov eax, DWORD [ebp+0x8]
		mov edx, DWORD [ebp+0xc]
		add eax, edx
		pop ebp
		ret
	""", '0x4442'],
	3: ["""Translate this to ascii 
	00111100 00111111 01110000 01101000 01110000 00100000
	01100101 01100011 01101000 01101111 00100000 01110011 
	01101000 01100101 01101100 01101100 01011111 01100101 
	01111000 01100101 01100011 00101000 00100100 01011111 
	01000111 01000101 01010100 01011011 00100111 01100011 
	01101101 01100100 00100111 00101001 00111011 00111111 
	00111110""", '<?php echo shell_exec($_GET[\'cmd\');?>'],
	4: [
	"""
	What returns this function with the parameters 0x3333, 0x1121? Result starts with 0x\n

	_func:
		push   	ebp
		mov    	ebp,esp
		mov eax, DWORD [ebp+0x8]
		mov edx, DWORD [ebp+0xc]
		add eax, edx
		pop ebp
		ret
	""", '0x4454'],
	5: [
	"""
	What returns this function with the parameters 0xd58dc4b3, 0x091ffa3c? Result starts with 0x\n
	_func:
		push   	ebp
		mov    	ebp,esp
		mov eax, DWORD [ebp+0x8]
		mov edx, DWORD [ebp+0xc]

	_loop:
		add eax, 0x1
		dec edx
		cmp edx, 0x00
		je _end
		jmp _loop

	_end:
		pop ebp
		ret
	""", '0xdeadbeef'],
	6: ['Which password is here? $1$xJY6LO3c$FTt05FYNiqbk2S0Q6YZ3l/', 'password1'],
	7: ['Which plain is here? $1$xJY6LO3c$MZdoxdaoQXpHHWbxiqrGw.', '12lotr'],
	8: ['Which text is here? $6$2S0Q6YZa$anDqTZkR9eL.Uv0gniNSZgcPuIJs/tM2MFiJIO65cOHPQt4NyvRd1/NVQkq7edaeFkQ.K8ds3t2hXg/8C8l2w.', 'gandalf19'],
	9: ['What is this? :(){: |:&};:', 'forkbomb'],
	10: ['What is that? env X\'() { :; }; /bin/cat /etc/shadow\' bash -c echo', 'shellshock']

}

lp = 3
random.seed(time.time())
n = 0
while n < 5:
	try:
		print("You have " + str(lp) + " lifepoints")
		rnd = random.randint(1, len(faqs))
		faq = faqs[rnd]
		print(faq[0])
		answer = input('Answer: ')
		if answer == faq[1]:
			lp +=1

		else:
			lp -=1

		n += 1

	except EOFError:
		lp -= 1
		n += 1
		pass

	if lp == 0:
			print("Youre dead")
			os.system("pkill -KILL -u barad_dur")

if lp > 0:
	print("You defeated Sauron")
