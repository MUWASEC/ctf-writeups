#1588453271
import random
with open('flag.pdf.enc','rb') as myfile:
    content = myfile.read()[6:]

random.seed(1588453271)

found = ""
ss = []
for i in range(len(content)):
    found += chr(content[i]^random.randint(0, 255))
with open("res.pdf", 'wb') as myfile:
    myfile.write(found.encode('charmap'))
