import sys
import os
import hashlib
import zlib
import io
import imp

import scanmod
import curemod

ViruseDB = []
vdb = []
vsize = []
sdb = []

def DecodeKMD(fname):
    print ('Try decoding the VirusDB')
    try :
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

#        print ('reading_done')
        buf2 = buf[:-32]
#        print (buf2)
        fmd5 = buf[-32:]
#        print ('content : %s' % buf2)
#        print ('md5_hash : %s' % fmd5)

        f = buf2
        for i in range(3):
            md5 = hashlib.md5()
            md5.update(f)
            f = md5.hexdigest()

        if f != fmd5:
            print ('VirusDB is modified!!!')
            raise SystemError

        buf3 = ''
        for c in buf2[4:]:
            buf3 += chr(ord(c) ^ 0xff)

        buf4 = zlib.decompress(buf3)
        print ('Decoding complete')
#        print (buf4)
        return buf4
    except:
        pass
    
    return None

def LoadVirusDB():
    print ('Start Loading VirusDB...')
    buf = DecodeKMD('virus.kmd').decode()
    fp = io.StringIO(buf)

    while  True :
        line = fp.readline()
        line = str(line)
        if not line : break

        line = line.strip()
        ViruseDB.append(line)

    fp.close()
#    print (list(ViruseDB))
    print ('Load_complete!')
    print ('')

def MakeVirusDB():
    for pattern in ViruseDB:
        t = []
        v = pattern.split(':')

        scan_func = v[0]
        cure_func = v[1]
        if scan_func == 'ScanMD5':
            t.append(v[3])
            t.append(v[4])
            vdb.append(t)

            size = int(v[2])
            if vsize.count(size) == 0:
                vsize.append(size)
        elif scan_func == 'ScanStr':
            t.append(int(v[2]))
            t.append(v[3])
            t.append(v[4])
            sdb.append(t)

if __name__ == '__main__':
    if len(sys.argv) != 2 :
        print ('Usage : antivirus.py [file]')
        sys.exit(0)
    
    LoadVirusDB()
    MakeVirusDB()

    fname = sys.argv[1]

    try :
        print ('try importing...')
        m = 'scanmod'
        f, filename, desc = imp.find_module(m, [''])
        module = imp.load_module(m, f, filename, desc)
        cmd = 'ret, vname = module.ScanVirus(vdb, vsize, sdb, fname)'
        print ('done!')
        exec cmd
    except ImportError :
        print 'fail!'
        ret,vname = scanmod.ScanVirus(vdb, vsize, sdb, fname)
    
    if ret == True :
        print ('Virus is detected!!')
        print ('%s : %s' %(fname, vname))
        curemod.CureDelete(fname)
    else :
        print ('%s : ok ' %(fname))

