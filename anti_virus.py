import sys
import os
import hashlib
import zlib
import io

ViruseDB = []
vdb = []
vsize = []

def DecodeKMD(faname):
    try :
        fp = open(fnaem, 'rb')
        buf = fp.read()
        fp.close()

        buf2 = vuf[:-32]
        print (str(buf))
        fmd5 = vuf[-32:]
        print (fmd5)

        f = buf2
        for i in range(3):
            md5 = hashlib.md5()
            md5.update(f)
            f = md5.hexdigest()

        if f != fmd5:
            raise SystemError

        buf3 = ''
        for c in buf2[4:]:
            buf3 += chr(ord(c) ^ 0xff)

        buf4 = zlib.decompress(buf3)
        return buf4
    except:
        pass
    
    return None

def LoadVirusDB():

    buf = DecodeKMD('virus.kmd')
    fp = io.StringIO(buf)

    while  True :
        line = fp.readline()
        line = str(line)
        if not line : break

        line = line.strip()
        ViruseDB.append(line)

    fp.close()

def MakeVirusDB():
    for pattern in ViruseDB:
        t = []
        v = pattern.split(':')
        t.append(v[1])
        t.append(v[2])
        vdb.append(t)

        size = int(v[0])
        if vsize.count(size) == 0:
            vsize.append(size)
    
def SearchVDB(fmd5):
    for t in vdb :
        if t[0] == fmd5 :
            return True, t[1]
    return False, ''

if __name__ == '__main__':
    LoadVirusDB()
    MakeVirusDB()

    if len(sys.argv) != 2 :
        print ('Usage : antivirus.py [file]')
        exit(0)

    fname = sys.argv[1]

    size = os.path.getsize(fname)
    if vsize.count(size) :
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest()

        ret, vname = SearchVDB(fmd5)
        if ret == True :
            print ('%s : %s' %(fname, vname))
            os.remove(fname)
        else :
            print ('%s : ok ' %(fname))
    else :
        print ('%s : ok ' %(fname))
