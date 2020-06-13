#!/usr/bin/python2
import sys
import pyfiglet
import random
sys.stdout.flush()
def print_flag():
	flag=open("flag.txt",'r').read()
	print "WTF even input is vulnerable ? "
	print flag
	
def header():
	f =pyfiglet.Figlet(font='slant')
	print f.renderText('GUESSY GAME')
	print "\t\t** Beta Version bad ppl may exploit it **"
try:
	header()
	while True:
		you_cant_guess_me=random.randint(10,80)
		number=input("Your input: ")
		print number
		if number==you_cant_guess_me:
			print_flag()
		else:
			print "You won't guess it trust me :( But maybe you can pwn it ? ;)"
except :
	print(number)
	print "\nBye Bye don't come back :D"
