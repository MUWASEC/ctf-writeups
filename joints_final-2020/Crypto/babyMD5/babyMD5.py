#!/usr/bin/python
from hashlib import md5
import sys
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

guest_token="4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2c91388ff29d5b612fa918ec5a93adc02deb3ffbb79cd5ea6beaf86e3c46baf075e6739f3513a9e21a7fd17e6fe28a386938a6f81d31afd816394a0288dfce2b0".decode('hex')

def main():
    print("""
 __      __       .__                               
/  \    /  \ ____ |  |   ____  ____   _____   ____  
\   \/\/   // __ \|  | _/ ___\/  _ \ /     \_/ __ \ 
 \        /\  ___/|  |_\  \__(  <_> )  Y Y  \  ___/ 
  \__/\  /  \___  >____/\___  >____/|__|_|  /\___  >
       \/       \/          \/            \/     \/ 
""")
    try:
        while True:
            print("""
1).Guest signature
2).Login
3).Exit
        """)
            print("""Select menu:""")
            op = raw_input()
            if op == "1":
                print(md5(guest_token+"&guest").hexdigest())
            elif op == "2":
                print("""Token:""")
                token, user = raw_input().split("&")
                token=token.decode("hex")
                if md5(token).hexdigest()!=md5(guest_token).hexdigest():
                    print("Login failed")
                else:
                    sign1=md5(guest_token+"&"+user).hexdigest()
                    sign2=md5(token+"&"+user).hexdigest()
                    if sign1==sign2 and token!=guest_token and user!="guest":
                        f=open("flag.txt","r").read()
                        print(f)
                        exit(0)
                    else:
                        print("Sorry !!!")
            else:
                print("Exit")
                exit(0)
    except Exception:
        print("Error occurred")
        exit(0)

if __name__ == '__main__':
    main()


