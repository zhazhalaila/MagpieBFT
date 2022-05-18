#!/usr/bin/python3
# Using re to find which acs instance not exit
import re

with open('log2.txt') as file:
    lines = file.readlines()


d = {}
for i in range(0,499):
    s = str(i) + '] acs exit'
    for line in lines:
        if line.endswith('acs exit.\n'):
            if re.search(s, line) != None:
                d[i] = line
                break


for i in range(0, 499):
    try:
        d[i]
    except:
        print(i)