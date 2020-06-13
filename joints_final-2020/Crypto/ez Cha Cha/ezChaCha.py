#!/usr/bin/python
from salsa20 import XSalsa20_xor
from os import urandom
import random
import sys

IV = urandom(24)
KEY = urandom(32)

ID=int(urandom(2).encode('hex'), 16)
random.seed(ID)

class Unbuffered(object):
   def __init__(self, stream):
       self.stream = stream
   def write(self, data):
       self.stream.write(data)
       self.stream.flush()
   def writelines(self, datas):
       self.stream.writelines(datas)
       self.stream.flush()
   def __getattr__(self, attr):
       return getattr(self.stream, attr)

sys.stdout = Unbuffered(sys.stdout)

def chaCha(plaintext,IV,KEY):
    return XSalsa20_xor(plaintext, IV, KEY)

def getFlag():
    f=open("flag.txt",'r').read()
    return f

def randomPad(length):
    pad=""
    for i in range(length):
        pad+=urandom(length)
    return pad

def main():

    print("""
 _    _      _                             ___                   _     _____ _           _____ _           
| |  | |    | |                           / _ \                 | |   /  __ \ |         /  __ \ |          
| |  | | ___| | ___ ___  _ __ ___   ___  / /_\ \ __ _  ___ _ __ | |_  | /  \/ |__   __ _| /  \/ |__   __ _ 
| |/\| |/ _ \ |/ __/ _ \| '_ ` _ \ / _ \ |  _  |/ _` |/ _ \ '_ \| __| | |   | '_ \ / _` | |   | '_ \ / _` |
\  /\  /  __/ | (_| (_) | | | | | |  __/ | | | | (_| |  __/ | | | |_  | \__/\ | | | (_| | \__/\ | | | (_| |
 \/  \/ \___|_|\___\___/|_| |_| |_|\___| \_| |_/\__, |\___|_| |_|\__|  \____/_| |_|\__,_|\____/_| |_|\__,_|
                                                 __/ |                                                     
                                                |___/                                                      
    """)

    print("Agent id "+str(ID))
    FLAG=getFlag()
    pad_list=[randomPad(random.randint(1,10)),randomPad(random.randint(1,10)),randomPad(random.randint(1,10))]
            
    for i in range(int(urandom(2).encode('hex'), 16)):
        random.shuffle(pad_list)
                
    flag=chaCha(FLAG,IV,KEY)
    encrypted_flag=pad_list[0]+flag[len(flag)/2:]+pad_list[1]+flag[:len(flag)/2]+pad_list[2]
    
    try:
        while True:
            print("""
    1).Encrypted Flag
    2).Encrypt data
    3).Check Flag
            """)
            print("""Select menu:""")
            op = raw_input()

            if op == "1":
                print(encrypted_flag.encode("hex"))

            elif op == "2":
                msg=raw_input(">> ")
                msg=msg[0]*len(msg)
                print(chaCha(msg,IV,KEY).encode("hex"))
            elif op== "3":
                msg=raw_input(">> ")
                if msg==FLAG:
                    print("JOINTS20{%s}"% msg)
                else:
                    print("Wrong !!")

            else:
                print("Exit")
                exit(0)

    except Exception:
        print("Error occurred")
        exit(0)

if __name__ == "__main__":
    main()