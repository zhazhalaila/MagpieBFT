#!/usr/bin/python3
 
import re

with open('log2.txt') as file:
    lines = file.readlines()


d = {}
for i in range(1000,2000):
    s = str(i) + '] ABA exit'
    for line in lines:
        if line.endswith('ABA exit.\n'):
            if re.search(s, line) != None:
                d[i] = line
                break

for i in range(1000, 2000):
    try:
        d[i]
    except:
        print(i)

print(len(d))