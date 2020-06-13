#!/usr/bin/env python
from itertools import product
from sys import path
from os import putenv

path=''
putenv("PYTHONPATH","/usr/lib/python2.7/dist-packages/more_itertools/")
for i in product("tryhardertryhardertryharder",repeat=1):
	print ''.join(i)

