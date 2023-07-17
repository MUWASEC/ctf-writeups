import random 
import time


magic = [0x25,  0x50,  0x44,  0x46, 0x2d]

with open('flag.pdf.enc', encoding='charmap') as myfile:
    content = myfile.read()[6:6+len(magic)]


for i in range(1588177600, 1588377600  + 86400):
    random.seed(i)
    found = True
    for j in range(len(magic)):
        if ord(content[j])^random.randint(0, 255) != magic[j]:
            found = False
            break
    if found:
        print("found")
        print(i)
