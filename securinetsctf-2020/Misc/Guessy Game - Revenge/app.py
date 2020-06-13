import pyfiglet,random
def print_flag():
        print "WTF there's no game and you won :o "
        print "Oh i have also forgot to read the flag :("

def header():
        f =pyfiglet.Figlet(font='slant')
        print f.renderText('Revenge GAME')
        print "\t\t** Maybe a talented hacker can exploit it ? **"
header()
try:
	print "I decided to ruin the game :D You cant pwn it now"
	while True:
		you_cant_guess_me=random.randint(10,60)
		number=input("Your input: ")
		if number==you_cant_guess_me:
			print "Hmmmm sorry i forgot to call print flag function :'( Good hackers will always find a solution"
		else:
			print "it's 2020 and ppl are not winning this game ?"
except :
	print "\nBye Bye please dont come back :D"
