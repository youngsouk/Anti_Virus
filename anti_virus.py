import sys
import os
import hashlib

ViruseDB = []
vdb = []
vsize = []

def LoadVirusDB():
        fp = open('virus.db', 'rb')

        while  True :
            line = fp.readline()
            if not line : break;
            
            line = line.strip()
            ViruseDB.append(line)

        fp.close()
