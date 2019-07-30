import os
import hashlib

def SearchVDB(vdb, fmd5):
    for t in vdb:
#        print ('target : %s' % fmd5)
#        print ('virus_db : %s'%t[0])
        if t[0] == fmd5.upper():
            return True, t[1]

    return False, ''

def ScanMD5(vdb, vsize, fname):
    ret = False
    vname = ''

    size = os.path.getsize(fname)
#    print ('target : %d' % size)
#    print ('virus_db : %s'% list(vsize))
    if vsize.count(size) :
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest()

        ret, vname = SearchVDB(vdb,fmd5)
    return ret, vname

def ScanStr(fp, offset, mal_str):
    size = len(mal_str)

    fp.seek(offset)
    buf = fp.read(size)

    if(buf == mal_str):
        return True
    else:
        return False

def ScanVirus(vdb, vsize, sdb, fname):
    print ('scanning...')

    print ('trying md5...')
    ret, vname = ScanMD5(vdb, vsize, fname)
    if ret == True :
        return ret, vname
    print ('safe!')

    fp = open(fname, 'rb')
    print ('trying str...')
    for t in sdb :
        if ScanStr(fp, t[0], t[1]) == True:
            ret = True
            vname = t[2]
            break
    fp.close()

    print ('scanning done!')
    print ('')

    return ret, vname